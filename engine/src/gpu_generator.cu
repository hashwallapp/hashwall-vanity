#include <stdio.h>
#include <assert.h>

#include <curand_kernel.h>

#define CUDA_CHECK(call)                                              \
    do {                                                              \
        cudaError_t err = call;                                       \
        if (err != cudaSuccess) {                                     \
            fprintf(stderr, "CUDA Error in %s at %s:%d: %s\n", #call, \
                    __FILE__, __LINE__, cudaGetErrorString(err));     \
            exit(1);                                                  \
        }                                                             \
    } while (0)

#define NTHREADS (gridDim.x * blockDim.x)
#define TID (blockDim.x * blockIdx.x + threadIdx.x)
#define each_coal_tid(type, item, ptr, size, stride_offset) each_strided(type, item, ptr, size, TID, NTHREADS, stride_offset)
#include "slpng.c"
#include "third_party/sha256.cu"
#include "sha512.cu"
#include "ed25519.cu"
#include "db.cu"

__constant__ static char *seed_prefix   = "multisig";
__constant__ static char *seed_multisig = "multisig";
__constant__ static char *seed_vault    = "vault";
__constant__ static char *pda_postfix   = "ProgramDerivedAddress";
__constant__ static u8    program_id[32] = { 6, 129, 196, 206, 71, 226, 35, 104, 184, 177, 85, 94, 200, 135, 175, 9, 46, 252, 126, 251, 182, 108, 163, 245, 47, 191, 104, 212, 172, 156, 183, 168 };

#define MULTISIG_SEEDS_SIZE (8 + 8 + 32 + 1 + 32 + 21) // "multisig" + "multisig" + pk + bump + program_id + "ProgramDerivedAddress"
#define VAULT_SEEDS_SIZE (8 + 32 + 5 + 1 + 1+ 32 + 21) // "multisig" + multisig_pda + "vault" + index + bump + program_id + "ProgramDerivedAddress"

typedef struct {
    curandStateMRG32k3a *curand_states;
    u32 *ed25519_seeds;
    u32 *public_keys;
    u32 *multisig_pdas;
    u32 *multisig_bumps;
    u32 *vault_pdas;
    u32 *vault_bumps;
    u32 *is_off_curve;
    u32 *vault_pdas_b58;
    u32 *found;
} DeviceMemory;

TYPEDEF_ARENA_UNION(DeviceMemory);

void copy_device_memory(DeviceMemory *dst, Arena *dst_arena, DeviceMemory *src, Arena *src_arena) {
#if 0
    dst->curand_states  = (curandStateMRG32k3a *)((uptr)(dst_arena->memory) + arena_get_offset(src_arena, (uptr)src->curand_states));
    dst->ed25519_seeds  =                 (u32 *)((uptr)(dst_arena->memory) + arena_get_offset(src_arena, (uptr)src->ed25519_seeds));
    dst->public_keys    =                 (u32 *)((uptr)(dst_arena->memory) + arena_get_offset(src_arena, (uptr)src->public_keys));
    dst->multisig_pdas  =                 (u32 *)((uptr)(dst_arena->memory) + arena_get_offset(src_arena, (uptr)src->multisig_pdas));
    dst->multisig_bumps =                 (u32 *)((uptr)(dst_arena->memory) + arena_get_offset(src_arena, (uptr)src->multisig_bumps));
    dst->vault_pdas     =                 (u32 *)((uptr)(dst_arena->memory) + arena_get_offset(src_arena, (uptr)src->vault_pdas));
    dst->vault_bumps    =                 (u32 *)((uptr)(dst_arena->memory) + arena_get_offset(src_arena, (uptr)src->vault_bumps));
    dst->is_off_curve   =                 (u32 *)((uptr)(dst_arena->memory) + arena_get_offset(src_arena, (uptr)src->is_off_curve));
    dst->vault_pdas_b58 =                 (u32 *)((uptr)(dst_arena->memory) + arena_get_offset(src_arena, (uptr)src->vault_pdas_b58));
    dst->found          =                 (u32 *)((uptr)(dst_arena->memory) + arena_get_offset(src_arena, (uptr)src->found));
#else
    arena_copy_offsets(dst, dst_arena, src, src_arena, DeviceMemory);
#endif
}

__constant__ u64 d_urandom_seed;
__global__ void init_curand_states(DeviceMemory memory) {
    //curand_init(5051, TID, 0, memory.curand_states + TID);
    curand_init(d_urandom_seed, TID, 0, memory.curand_states + TID);
}

__constant__ char b58digits_ordered[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

__device__ __forceinline__ unsigned int fast_div58(unsigned int x) {
    return (x * 1130u) >> 16u;
}

__device__ __forceinline__ unsigned int fast_mod58(unsigned int x) {
    return x - fast_div58(x) * 58u;
}

__device__ bool b58enc(char *b58, unsigned int *b58sz, const unsigned char *data, unsigned int binsz) {
    const unsigned char *bin = data;
    unsigned int carry;
    unsigned int i, j, high, zcount = 0;
    unsigned int size;

    while (zcount < binsz && !bin[zcount])
        ++zcount;

    size = (binsz - zcount) * 138 / 100 + 1;

    unsigned char buf[45];
    for (i = 0; i < 45; ++i) buf[i] = 0;

    for (i = zcount, high = size - 1; i < binsz; ++i, high = j) {
        for (carry = bin[i], j = size - 1; (j > high) || carry; --j) {
            carry += 256u * buf[j];
            buf[j] = (unsigned char)fast_mod58(carry);
            carry = fast_div58(carry);
            if (!j) break;
        }
    }

    for (j = 0; j < size && !buf[j]; ++j);

    if (*b58sz <= zcount + size - j) {
        *b58sz = zcount + size - j + 1;
        return false;
    }

    if (zcount) {
        for (i = 0; i < zcount; ++i) b58[i] = '1';
    }
    for (i = zcount; j < size; ++i, ++j) {
        b58[i] = b58digits_ordered[buf[j]];
    }

    b58[i] = '\0';
    *b58sz = i + 1;
    return true;
}

__device__ int global_found = 0;

typedef struct {
    u32 is_on_curve;
    u32 pda[SHA256_DIGEST_LENGTH/sizeof(u32)];
    u32 bump;
} PdaResult;

__device__
PdaResult find_multisig_pda(u8 pub_key[ED25519_PUB_KEY_SIZE]) {
    PdaResult result = {0};

    u8 seeds[MULTISIG_SEEDS_SIZE];
    u8 bump = 255;

    int cursor = 0;
    int bump_offset = 0;

    for (int i = 0; i < 8; i++)  { seeds[cursor++] = seed_prefix[i]; }
    for (int i = 0; i < 8; i++)  { seeds[cursor++] = seed_multisig[i]; }
    for (int i = 0; i < 32; i++) { seeds[cursor++] = pub_key[i]; }
    bump_offset = cursor;
                                   seeds[cursor++] = bump;
    for (int i = 0; i < 32; i++) { seeds[cursor++] = program_id[i]; }
    for (int i = 0; i < 21; i++) { seeds[cursor++] = pda_postfix[i]; }

    int is_on_curve = 1;
    for (int bumps = 0; bumps < 1 && is_on_curve; bumps++) {
        SHA256(seeds, MULTISIG_SEEDS_SIZE, (u8 *)result.pda);
        is_on_curve = is_valid_point((u8 *)result.pda);
        bump -= 1;
        seeds[bump_offset] = bump;
    }

    result.is_on_curve = is_on_curve;
    result.bump = bump + 1;

    return result;
}

__device__
PdaResult find_vault_pda(u8 multisig_pda[32], u8 vault_index) {
    PdaResult result = {0};

    u8 seeds[VAULT_SEEDS_SIZE];
    u8 bump = 255;

    int cursor = 0;
    int bump_offset = 0;

    for (int i = 0; i < 8; i++)  { seeds[cursor++] = seed_prefix[i]; }
    for (int i = 0; i < 32; i++) { seeds[cursor++] = multisig_pda[i]; }
    for (int i = 0; i < 5; i++)  { seeds[cursor++] = seed_vault[i]; }
                                   seeds[cursor++] = vault_index;
    bump_offset = cursor;
                                   seeds[cursor++] = bump;
    for (int i = 0; i < 32; i++) { seeds[cursor++] = program_id[i]; }
    for (int i = 0; i < 21; i++) { seeds[cursor++] = pda_postfix[i]; }

    int is_on_curve = 1;
    for (int bumps = 0; bumps < 1 && is_on_curve; bumps++) {
        SHA256(seeds, VAULT_SEEDS_SIZE, (u8 *)result.pda);
        is_on_curve = is_valid_point((u8 *)result.pda);
        bump -= 1;
        seeds[bump_offset] = bump;
    }

    result.is_on_curve = is_on_curve;
    result.bump = bump + 1;

    return result;
}

__global__ void kernel(DeviceMemory memory) {
    char prefix[4] = "SAS";
    int prefix_size = 3;

    for (int i = 0; i < 1; i++) {
        if (global_found) break;

        //
        // random seeds
        //

        for each_coal(it, index, ED25519_SEED_SIZE) {
            u32 chunk = curand(memory.curand_states + TID);
            memory.ed25519_seeds[it] = chunk;
        }

        //
        // ed25519
        //

        uint32_t m[SHA512_BLOCK_LENGTH/sizeof(u32)];

        uint64_t state[8];
        sha512_init_state(state);

        {
            int cursor = 0;
            for each_coal(it, idx, ED25519_SEED_SIZE) { m[cursor++] = memory.ed25519_seeds[it]; }
                                                        m[cursor++] = 0x80000000;
            for (int i = cursor; i < 128/4-1; i++)    { m[cursor++] = 0; }
                                                        m[cursor++] = ED25519_SEED_SIZE*8;
        }

        sha512_transform_state(state, m, SHA512_OUTPUT_DATA, SHA512_DATA_MEMORY_LOCAL);

        // because ed25519 operates on individual chars
        for (int i = 0; i < ED25519_SEED_SIZE/4; i++) { m[i] = __nv_bswap32(m[i]); }

        ge25519_p3 A;
        u8 *priv_key = (u8 *)m;
        u8 pub_key[ED25519_PUB_KEY_SIZE];

        priv_key[0] &= 248;
        priv_key[31] &= 63;
        priv_key[31] |= 64;

        ge25519_scalarmult_base(&A, priv_key);
        ge25519_p3_tobytes(pub_key, &A);

        for each_coal(it, index, ED25519_PUB_KEY_SIZE) {
            memory.public_keys[it] = *((uint32_t *)pub_key + index);
        }

        //
        // MULTISIG PDA
        //

        PdaResult multisig_pda = find_multisig_pda(pub_key);

        // TODO: BARRIER

        if (!multisig_pda.is_on_curve) {
#if 0
            for each_coal(it, index, 32) {
                memory.multisig_pdas[it] = multisig_pda.pda[index];
            }

            for each_coal(it, index, sizeof(u32)) {
                memory.multisig_bumps[it] = multisig_pda.bump;
            }
#endif

            //
            // VAULT PDA
            //

            PdaResult vault_pda = find_vault_pda((u8 *)multisig_pda.pda, 0);

            // TODO: BARRIER

            if (!vault_pda.is_on_curve) {
#if 0
                for each_coal(it, index, 32) {
                    memory.vault_pdas[it] = vault_pda.pda[index];
                }

                for each_coal(it, index, sizeof(u32)) {
                    memory.vault_bumps[it] = vault_pda.bump;
                }
#endif

                //
                // base58
                //

                char b58[48] = {0};
                u32 b58_size = 45;
                b58enc(b58, &b58_size, (u8 *)vault_pda.pda, 32);

                //
                // check prefix
                //

                int should_break = 0;
                for (int word_length = MAX_WORD_LENGTH; word_length >= 1; word_length -= 1) {
                    if (should_break) break;

                    Arena wordlist = d_wordlists[word_length - 1];
                    int word_count = wordlist.used / word_length;
                    for (int word_index = 0; word_index < word_count; word_index += 1) {
                        if (should_break) break;

                        int word_offset = word_index * word_length;
                        u8 *word = (u8 *)wordlist.memory + word_offset;

                        int still_matches = 1;
                        for (int i = 0; i < word_length; i += 1) {
                            still_matches &= word[i] == b58[i];
                        }

                        for each_coal_tid(u32, found, memory.found, sizeof(u32), current_run) {
                            *found.data = still_matches;
                        }

                        should_break = still_matches;
                    }
                }
            }
        }

        // TODO: BARRIER
    }
}

int main(int argc, char **argv) {
    Arena host_arena = {0};
    uptr host_memory_size = 2*1024*1024*1024LL;
    void *host_memory = malloc(host_memory_size);
    arena_init(&host_arena, host_memory, host_memory_size);

    //
    // parse command line arguments
    //

    Flag_Parser_Options options = {0};
    options.program_name = string_view_from_cstr(argv[0]);
    options.max_flags = 4;
    options.backing_arena = &host_arena;
    Flag_Parser parser = flag_parser_init(options);

    u64 runs_per_dispatch = 1; flag_parser_bind(&parser, FLAG_TYPE_U64,         &runs_per_dispatch, false, "runs", "amount of runs per kernel dispatch");
    String_View db_name = {0}; flag_parser_bind(&parser, FLAG_TYPE_STRING_VIEW, &db_name,           true,  "db",   "path to sqlite .db file");

    flag_parser_parse(&parser, argc, argv);

    printf("CONFIGURATION\n"
           "database name:     %.*s\n"
           "runs per dispatch: %lu\n"
           "\n",
           (int)db_name.length, db_name.bytes,
           runs_per_dispatch);

    //
    // init sqlite
    //

    // NOTE: this conversion is redundant since db_name string view points to
    // a command line argument which is already null-terminated. but it's
    // probably better to keep it in case db_name get trimmed or becomes a
    // string of a larger string later
    char *db_name_cstr = string_view_to_cstr(db_name, &host_arena);

    sqlite3 *db;
    SQLITE_CHECK(sqlite3_open(db_name_cstr, &db));
    prepare_sql_statements(db);

    //
    // query device properties
    //

    cudaDeviceProp prop = {0};
    CUDA_CHECK(cudaGetDeviceProperties(&prop, 0));

    int max_threads_per_sm = prop.maxThreadsPerMultiProcessor;
    int sm_count = prop.multiProcessorCount;
    int total_threads = max_threads_per_sm * sm_count;

    printf("DEVICE PROPERTIES\n"
           "device name:           %s\n"
           "max threads per sm:    %d\n"
           "sm count:              %d\n"
           "total threads:         %d\n"
           "total global memory:   %zu MB\n"
           "total constant memory: %zu B\n"
           "\n",
           prop.name, max_threads_per_sm, sm_count, total_threads, prop.totalGlobalMem/1024/1024, prop.totalConstMem);

    //
    // init memory
    //

    // device memory and arena
    u64 device_buffer_size = 1*1024*1024*1024;
    void *device_buffer;
    cudaMalloc(&device_buffer, device_buffer_size);
    cudaMemset(device_buffer, 0, device_buffer_size);

    Arena device_arena;
    arena_init(&device_arena, device_buffer, device_buffer_size);

    DeviceMemory device_memory = {0};
    device_memory.curand_states  =        arena_push_array(&device_arena, total_threads*runs_per_dispatch,                      curandStateMRG32k3a, sizeof(curandStateMRG32k3a));
    device_memory.ed25519_seeds  = (u32 *)arena_push_array(&device_arena, total_threads*runs_per_dispatch*ED25519_SEED_SIZE,    u8,                  sizeof(u32));
    device_memory.public_keys    = (u32 *)arena_push_array(&device_arena, total_threads*runs_per_dispatch*ED25519_PUB_KEY_SIZE, u8,                  sizeof(u32));
    device_memory.multisig_pdas  = (u32 *)arena_push_array(&device_arena, total_threads*runs_per_dispatch*SHA256_DIGEST_LENGTH, u8,                  sizeof(u32));
    device_memory.multisig_bumps =        arena_push_array(&device_arena, total_threads*runs_per_dispatch,                      u32,                 sizeof(u32));
    device_memory.vault_pdas     = (u32 *)arena_push_array(&device_arena, total_threads*runs_per_dispatch*SHA256_DIGEST_LENGTH, u8,                  sizeof(u32));
    device_memory.vault_bumps    =        arena_push_array(&device_arena, total_threads*runs_per_dispatch,                      u32,                 sizeof(u32));
    device_memory.is_off_curve   =        arena_push_array(&device_arena, total_threads*runs_per_dispatch,                      u32,                 sizeof(u32));
    device_memory.vault_pdas_b58 = (u32 *)arena_push_array(&device_arena, total_threads*runs_per_dispatch*48,                   u8,                  sizeof(u32));
    device_memory.found          =        arena_push_array(&device_arena, total_threads*runs_per_dispatch,                      u32,                 sizeof(u32));

    // device memory host mirror
    Arena mirror_arena;
    arena_make_subarena(&mirror_arena, &host_arena, device_buffer_size, 256);
    memset(mirror_arena.memory, 0, mirror_arena.capacity);

    DeviceMemory mirror = {0};
    copy_device_memory(&mirror, &mirror_arena, &device_memory, &device_arena);

    // TODO: remove later
    assert((u8 *)mirror.curand_states  - (u8 *)mirror_arena.memory == (u8 *)device_memory.curand_states  - (u8 *)device_arena.memory);
    assert((u8 *)mirror.ed25519_seeds  - (u8 *)mirror_arena.memory == (u8 *)device_memory.ed25519_seeds  - (u8 *)device_arena.memory);
    assert((u8 *)mirror.public_keys    - (u8 *)mirror_arena.memory == (u8 *)device_memory.public_keys    - (u8 *)device_arena.memory);
    assert((u8 *)mirror.multisig_pdas  - (u8 *)mirror_arena.memory == (u8 *)device_memory.multisig_pdas  - (u8 *)device_arena.memory);
    assert((u8 *)mirror.multisig_bumps - (u8 *)mirror_arena.memory == (u8 *)device_memory.multisig_bumps - (u8 *)device_arena.memory);
    assert((u8 *)mirror.vault_pdas     - (u8 *)mirror_arena.memory == (u8 *)device_memory.vault_pdas     - (u8 *)device_arena.memory);
    assert((u8 *)mirror.vault_bumps    - (u8 *)mirror_arena.memory == (u8 *)device_memory.vault_bumps    - (u8 *)device_arena.memory);
    assert((u8 *)mirror.is_off_curve   - (u8 *)mirror_arena.memory == (u8 *)device_memory.is_off_curve   - (u8 *)device_arena.memory);
    assert((u8 *)mirror.vault_pdas_b58 - (u8 *)mirror_arena.memory == (u8 *)device_memory.vault_pdas_b58 - (u8 *)device_arena.memory);
    assert((u8 *)mirror.found          - (u8 *)mirror_arena.memory == (u8 *)device_memory.found          - (u8 *)device_arena.memory);

    // wordlist arena
    Arena wordlist_arena;
    arena_make_subarena(&wordlist_arena, &host_arena, WORDLIST_SIZE, 256);

    // TODO: wordlist arena device mirror
#if 0
    Arena d_wordlist_arena;
    void *d_wordlist_memory;
    cudaMalloc(&d_wordlist_memory, WORDLIST_SIZE);
    arena_init(&d_wordlist_arena, d_wordlist_memory, WORDLIST_SIZE);
#endif

    //
    // init curand states
    //

    u64 h_urandom_seed;
    FILE *fp = fopen("/dev/urandom", "rb");
    assert(fread(&h_urandom_seed, sizeof(u64), 1, fp) > 0);
    fclose(fp);

    CUDA_CHECK(cudaMemcpyToSymbol(
        d_urandom_seed,
        &h_urandom_seed,
        sizeof(u64),
        0,
        cudaMemcpyHostToDevice
    ));

    {
        int block_size = 256;
        assert(block_size <= prop.maxThreadsPerBlock);

        int blocks_per_sm = max_threads_per_sm / block_size;
        int grid_size = blocks_per_sm * sm_count;

        init_curand_states<<<grid_size, block_size>>>(device_memory);

        cudaError_t err = cudaGetLastError();
        assert(err == cudaSuccess);
    }

    //
    // find the optimal kernel configuration
    //

    reload_wordlist(&wordlist_arena);

    cudaEvent_t event_start, event_stop;
    cudaEventCreate(&event_start);
    cudaEventCreate(&event_stop);

    int best_block_size = 0;
    int best_multisig_bump_limit = 0;
    int best_vault_bump_limit = 0;
    float best_average_ms = 0;
    float best_points_per_second = 0;

    int tries = 1;

    for (int block_size = 32; block_size <= 1024; block_size *= 2) {
        int blocks_per_sm = max_threads_per_sm / block_size;
        int grid_size = blocks_per_sm * sm_count;

        for (int multisig_bump_limit = 1; multisig_bump_limit <= 4; multisig_bump_limit += 1) {
            for (int vault_bump_limit = 1; vault_bump_limit <= 4; vault_bump_limit += 1) {
                float total_ms = 0;
                int total_on_curve_points = 0;

                int runs = 10;
                assert(runs > 1);

                cudaError_t err = cudaErrorUnknown;

                for (int run = 0; run < runs; run += 1) {
                    cudaEventRecord(event_start);

                    kernel<<<grid_size, block_size>>>(device_memory, tries, multisig_bump_limit, vault_bump_limit);

                    cudaEventRecord(event_stop);
                    cudaEventSynchronize(event_stop);

                    err = cudaGetLastError();
                    if (!err) {
                        // ignore the warm-up run
                        if (run > 0) {
                            float ms = 0;
                            cudaEventElapsedTime(&ms, event_start, event_stop);
                            total_ms += ms;

                            CUDA_CHECK(cudaMemcpy(
                                mirror.is_off_curve, device_memory.is_off_curve,
                                total_threads*sizeof(u32),
                                cudaMemcpyDeviceToHost
                            ));

                            for (int tid = 0; tid < total_threads; tid += 1) {
                                if (mirror.is_off_curve[tid]) {
                                    total_on_curve_points += 1;
                                }
                            }
                        }
                    }
                }

                if (!err) {
                    float average_ms = total_ms / (runs - 1);
                    float average_on_curve_points = (float)total_on_curve_points / (runs - 1);
                    float points_per_second = average_on_curve_points * 1000 / average_ms;

                    if (points_per_second > best_points_per_second) {
                        best_block_size = block_size;
                        best_multisig_bump_limit = multisig_bump_limit;
                        best_vault_bump_limit = vault_bump_limit;
                        best_average_ms = average_ms;
                        best_points_per_second = points_per_second;
                    }

                    printf("kernel<<<grid_size:%d, block_size:%d>>>(..., runs_per_dispatch:%d, multisig_bump_limit:%d, vault_bump_limit:%d, ...) average exec time: %f ms (%f points/s)\n", grid_size, block_size, tries, multisig_bump_limit, vault_bump_limit, average_ms, points_per_second);
                }
            }
        }
    }

    printf("\n"
           "OPTIMAL CONFIGURATION\n"
           "block size:          %d\n"
           "multisig bump limit: %d\n"
           "vault bump limit:    %d\n"
           "-----------------------\n"
           "average ms:          %f\n"
           "points per second:   %f\n"
           "\n",
           best_block_size, best_multisig_bump_limit, best_vault_bump_limit, best_average_ms, best_points_per_second);

    //
    // main loop
    //

    int block_size = best_block_size;
    int blocks_per_sm = max_threads_per_sm / block_size;
    int grid_size = blocks_per_sm * sm_count;

    int found = 0;
    int cycles = 0;
#if 1
    while (!found)
#endif
    {
#if 1
        if (cycles % 100 == 0) {
            cycles = 0;
            reload_wordlist(&wordlist_arena);
        }
        cycles += 1;
#endif

        cudaEventRecord(event_start);
        {
            kernel<<<grid_size, block_size>>>(device_memory, runs_per_dispatch, best_multisig_bump_limit, best_vault_bump_limit);
            CUDA_CHECK(cudaDeviceSynchronize());
        }
        cudaEventRecord(event_stop);
        cudaEventSynchronize(event_stop);
        float ms = 0;
        cudaEventElapsedTime(&ms, event_start, event_stop);
        printf("kernel<<<grid_size:%d, block_size:%d>>>(..., runs_per_dispatch:%ld, multisig_bump_limit:%d, vault_bump_limit:%d) exec time: %f ms\n", grid_size, block_size, runs_per_dispatch, best_multisig_bump_limit, best_vault_bump_limit,  ms);

        CUDA_CHECK(cudaMemcpy(
            mirror.found, device_memory.found,
            total_threads*sizeof(u32),
            cudaMemcpyDeviceToHost
        ));

        for (int current_run = 0; current_run < runs_per_dispatch; current_run += 1) {
            for (int tid = 0; tid < total_threads; tid += 1) {
                if (mirror.found[tid]) {
                    CUDA_CHECK(cudaMemcpy(mirror.ed25519_seeds, device_memory.ed25519_seeds, total_threads*runs_per_dispatch*ED25519_SEED_SIZE*sizeof(u32),    cudaMemcpyDeviceToHost));
                    CUDA_CHECK(cudaMemcpy(mirror.public_keys,   device_memory.public_keys,   total_threads*runs_per_dispatch*ED25519_PUB_KEY_SIZE*sizeof(u32), cudaMemcpyDeviceToHost));
                    CUDA_CHECK(cudaMemcpy(mirror.vault_pdas,    device_memory.vault_pdas,    total_threads*runs_per_dispatch*32,                               cudaMemcpyDeviceToHost));

                    char keypair[256] = {0};
                    for each_strided(u32, seed, mirror.ed25519_seeds, ED25519_SEED_SIZE, tid, total_threads, current_run) {
                        u32 c = *seed.data;
                        char src[255] = {0};
                        stbsp_sprintf(src, "%d,%d,%d,%d,", (u8)(c >> 24), (u8)(c >> 16), (u8)(c >> 8), (u8)(c));
                        strcat(keypair, src);
                    }
                    for each_strided(u32, key, mirror.public_keys, ED25519_PUB_KEY_SIZE, tid, total_threads, current_run) {
                        u32 c = *key.data;
                        uptr index = key.index;
                        char src[255] = {0};
                        if (index < ED25519_PUB_KEY_SIZE/4 - 1) {
                            stbsp_sprintf(src, "%d,%d,%d,%d,", (u8)(c), (u8)(c >> 8), (u8)(c >> 16), (u8)(c >> 24));
                        } else {
                            stbsp_sprintf(src, "%d,%d,%d,%d", (u8)(c), (u8)(c >> 8), (u8)(c >> 16), (u8)(c >> 24));
                        }
                        strcat(keypair, src);
                    }

                    char pda[SHA256_DIGEST_LENGTH] = {0};
                    for each_strided(u32, item, mirror.vault_pdas, 32, tid, total_threads, current_run) {
                        *((u32 *)pda + item.index) = *item.data;
                    }

                    printf("keypair: \n"
                           "[%s]\n", keypair);

                    save_found_vault(db, keypair, pda);
                }
            }
        }
    }

    return 0;
}
