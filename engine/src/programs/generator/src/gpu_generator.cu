//
// libc
//

#include <stdio.h>
#include <assert.h>

//
// CUDA
//

#include <curand_kernel.h>

#define CUDA_CHECK(call)                                                  \
    do {                                                                  \
        cudaError_t err = call;                                           \
        if (err != cudaSuccess) {                                         \
            fprintf(stderr, "CUDA Error in %s at %s:%d: %s\n",            \
                    #call , __FILE__, __LINE__, cudaGetErrorString(err)); \
            exit(1);                                                      \
        }                                                                 \
    } while (0)

#define NTHREADS (gridDim.x * blockDim.x)
#define TID (blockDim.x * blockIdx.x + threadIdx.x)

#define each_strided_size_offset_by_size(type, item, ptr, size_in_bytes, offset, stride, current_run) \
            each_strided_size(type, item, ptr, size_in_bytes, offset, stride, current_run*size_in_bytes/sizeof(type))

#define each_coal_tid(type, item, ptr, size, current_run) each_strided_size_offset_by_size(type, item, ptr, size, TID, NTHREADS, current_run)
#define each_coal_tid_host(type, item, ptr, size, current_run) each_strided_size_offset_by_size(type, item, ptr, size, tid, total_threads, current_run)

//
// program
//

#include "base/base.h"
#include "base/base.c"

#include "third_party/sha256.cu"
#include "sha512.cu"
#include "ed25519.cu"
#include "db.cu"

#if HASHWALL_INTERNAL
#   include "third_party/libsodium/sodium.h" // for tests
#endif

#define SEED_PREFIX     "multisig"
#define SEED_MULTISIG   "multisig"
#define SEED_VAULT      "vault"
#define PDA_POSTFIX     "ProgramDerivedAddress"

#define PROGRAM_ID { 6, 129, 196, 206, 71, 226, 35, 104, 184, 177, 85, 94, 200, 135, 175, 9, 46, 252, 126, 251, 182, 108, 163, 245, 47, 191, 104, 212, 172, 156, 183, 168 }
#define PROGRAM_ID_SIZE 32

static String8 h_seed_prefix    = str8lit(SEED_PREFIX);
static String8 h_seed_multisig  = str8lit(SEED_MULTISIG);
static String8 h_seed_vault     = str8lit(SEED_VAULT);
static String8 h_pda_postfix    = str8lit(PDA_POSTFIX);
static u8      h_program_id[32] = PROGRAM_ID;

__constant__ static String8 d_seed_prefix;
__constant__ static String8 d_seed_multisig;
__constant__ static String8 d_seed_vault;
__constant__ static String8 d_pda_postfix;
__constant__ static u8      d_program_id[32] = PROGRAM_ID;

#define MULTISIG_SEEDS_SIZE (8 + 8 + 32 + 1 + 32 + 21) // "multisig" + "multisig" + pk + bump + program_id + "ProgramDerivedAddress"
#define VAULT_SEEDS_SIZE (8 + 32 + 5 + 1 + 1+ 32 + 21) // "multisig" + multisig_pda + "vault" + index + bump + program_id + "ProgramDerivedAddress"

void string8_copy_to_symbol(Arena *arena, const void *symbol, String8 *src) {
    String8 copy = {0};
    copy.bytes = arena_push_array_no_zero(arena, src->length, u8);
    copy.length = src->length;
    CUDA_CHECK(cudaMemcpy(copy.bytes, src->bytes, src->length, cudaMemcpyHostToDevice));
    CUDA_CHECK(cudaMemcpyToSymbol(symbol, &copy, sizeof(copy), 0, cudaMemcpyHostToDevice));
}

typedef struct {
    curandStateMRG32k3a *curand_states;
    u32 *ed25519_seeds;
    u32 *public_keys;
#if HASHWALL_INTERNAL
    u32 *multisig_pdas;
    u32 *multisig_bumps;
    u32 *multisig_is_off_curve;
    u32 *vault_pdas;
    u32 *vault_bumps;
#endif
    u32 *vault_is_off_curve;
    u32 *vault_pdas_b58;
    u32 *found;
} DeviceMemory;

TYPEDEF_ARENA_UNION(DeviceMemory);

void copy_device_memory(DeviceMemory *dst, Arena *dst_arena, DeviceMemory *src, Arena *src_arena) {
    arena_copy_offsets(dst, dst_arena, src, src_arena, DeviceMemory);
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

typedef struct {
    u32 is_on_curve;
    u32 pda[SHA256_DIGEST_LENGTH/sizeof(u32)];
    u32 bump;
} PdaResult;

__host__ __device__ int
write_multisig_pda_seeds(u8 seeds[MULTISIG_SEEDS_SIZE],
                         String8 seed_prefix, String8 seed_multisig,
                         u8 pub_key[ED25519_PUB_KEY_SIZE], u8 bump,
                         u8 program_id[PROGRAM_ID_SIZE], String8 pda_postfix)
{
    int cursor = 0;
    int bump_offset = 0;

    for (int i = 0; i < seed_prefix.length; i++)   { seeds[cursor++] = seed_prefix.bytes[i]; }
    for (int i = 0; i < seed_multisig.length; i++) { seeds[cursor++] = seed_multisig.bytes[i]; }
    for (int i = 0; i < ED25519_PUB_KEY_SIZE; i++) { seeds[cursor++] = pub_key[i]; }

    bump_offset = cursor;

                                                     seeds[cursor++] = bump;
    for (int i = 0; i < PROGRAM_ID_SIZE; i++)      { seeds[cursor++] = program_id[i]; }
    for (int i = 0; i < pda_postfix.length; i++)   { seeds[cursor++] = pda_postfix.bytes[i]; }

    assert(cursor == MULTISIG_SEEDS_SIZE);

    return bump_offset;
}

#if HASHWALL_INTERNAL
PdaResult find_multisig_pda_host(u8 pub_key[ED25519_PUB_KEY_SIZE], int bump_limit) {
    PdaResult result = {0};

    u8 seeds[MULTISIG_SEEDS_SIZE] = {0};
    u8 bump = 255;
    int bump_offset = write_multisig_pda_seeds(seeds,
                                               h_seed_prefix, h_seed_multisig,
                                               pub_key, bump,
                                               h_program_id, h_pda_postfix);

    int is_on_curve = 1;
    for (int bumps = 0; bumps < bump_limit && is_on_curve; bumps++) {
        int hash_error = crypto_hash_sha256((u8 *)result.pda, seeds, MULTISIG_SEEDS_SIZE);
        assert(!hash_error);
        is_on_curve = crypto_core_ed25519_is_valid_point((u8 *)result.pda);
        bump -= 1;
        seeds[bump_offset] = bump;
    }

    result.is_on_curve = is_on_curve;
    result.bump = bump + 1;

    return result;
}
#endif

__device__ PdaResult find_multisig_pda(u8 pub_key[ED25519_PUB_KEY_SIZE], int bump_limit) {
    PdaResult result = {0};

    u8 seeds[MULTISIG_SEEDS_SIZE] = {0};
    u8 bump = 255;
    int bump_offset = write_multisig_pda_seeds(seeds,
                                               d_seed_prefix, d_seed_multisig,
                                               pub_key, bump,
                                               d_program_id, d_pda_postfix);

    int is_on_curve = 1;
    for (int bumps = 0; bumps < bump_limit && is_on_curve; bumps++) {
        SHA256(seeds, MULTISIG_SEEDS_SIZE, (u8 *)result.pda);
        is_on_curve = is_valid_point((u8 *)result.pda);
        bump -= 1;
        seeds[bump_offset] = bump;
    }

    result.is_on_curve = is_on_curve;
    result.bump = bump + 1;

    return result;
}

__host__ __device__ int
write_vault_pda_seeds(u8 seeds[VAULT_SEEDS_SIZE],
                      String8 seed_prefix, String8 seed_vault,
                      u8 multisig_pda[SHA256_DIGEST_LENGTH], u8 bump, u8 vault_index,
                      u8 program_id[PROGRAM_ID_SIZE], String8 pda_postfix)
{
    int cursor = 0;
    int bump_offset = 0;

    for (int i = 0; i < seed_prefix.length; i++)   { seeds[cursor++] = seed_prefix.bytes[i]; }
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) { seeds[cursor++] = multisig_pda[i]; }
    for (int i = 0; i < seed_vault.length; i++)    { seeds[cursor++] = seed_vault.bytes[i]; }
                                                     seeds[cursor++] = vault_index;

    bump_offset = cursor;

                                                     seeds[cursor++] = bump;
    for (int i = 0; i < PROGRAM_ID_SIZE; i++)      { seeds[cursor++] = program_id[i]; }
    for (int i = 0; i < pda_postfix.length; i++)   { seeds[cursor++] = pda_postfix.bytes[i]; }

    assert(cursor == VAULT_SEEDS_SIZE);

    return bump_offset;
}

#if HASHWALL_INTERNAL
PdaResult find_vault_pda_host(u8 multisig_pda[32], u8 vault_index, int bump_limit) {
    PdaResult result = {0};

    u8 seeds[VAULT_SEEDS_SIZE];
    u8 bump = 255;
    int bump_offset = write_vault_pda_seeds(seeds,
                                            h_seed_prefix, h_seed_vault,
                                            multisig_pda, bump, vault_index,
                                            h_program_id, h_pda_postfix);

    int is_on_curve = 1;
    for (int bumps = 0; bumps < bump_limit && is_on_curve; bumps++) {
        int hash_error = crypto_hash_sha256((u8 *)result.pda, seeds, VAULT_SEEDS_SIZE);
        assert(!hash_error);
        is_on_curve = crypto_core_ed25519_is_valid_point((u8 *)result.pda);
        bump -= 1;
        seeds[bump_offset] = bump;
    }

    result.is_on_curve = is_on_curve;
    result.bump = bump + 1;

    return result;
}
#endif

__device__ PdaResult find_vault_pda(u8 multisig_pda[32], u8 vault_index, int bump_limit) {
    PdaResult result = {0};

    u8 seeds[VAULT_SEEDS_SIZE];
    u8 bump = 255;
    int bump_offset = write_vault_pda_seeds(seeds,
                                            d_seed_prefix, d_seed_vault,
                                            multisig_pda, bump, vault_index,
                                            d_program_id, d_pda_postfix);

    int is_on_curve = 1;
    for (int bumps = 0; bumps < bump_limit && is_on_curve; bumps++) {
        SHA256(seeds, VAULT_SEEDS_SIZE, (u8 *)result.pda);
        is_on_curve = is_valid_point((u8 *)result.pda);
        bump -= 1;
        seeds[bump_offset] = bump;
    }

    result.is_on_curve = is_on_curve;
    result.bump = bump + 1;

    return result;
}

__global__ void reset_memory(DeviceMemory memory, int runs_per_dispatch) {
    for (int current_run = 0; current_run < runs_per_dispatch; current_run += 1) {
        for each_coal_tid(u32, it, memory.vault_is_off_curve, sizeof(u32), current_run) {
            *it.data = 0;
        }
        for each_coal_tid(u32, it, memory.found, sizeof(u32), current_run) {
            *it.data = 0;
        }
    }
}

__global__ void kernel(DeviceMemory memory, int runs_per_dispatch, int multisig_bump_limit, int vault_bump_limit) {
    for (int current_run = 0; current_run < runs_per_dispatch; current_run += 1) {
        //
        // random seeds
        //

        for each_coal_tid(u32, seed_chunk, memory.ed25519_seeds, ED25519_SEED_SIZE, current_run)
        {
            u32 chunk = curand(memory.curand_states + TID);
            *seed_chunk.data = chunk;
        }

        //
        // ed25519
        //

        uint32_t m[SHA512_BLOCK_LENGTH/sizeof(u32)];

        uint64_t state[8];
        sha512_init_state(state);

        {
            int cursor = 0;

            for each_coal_tid(u32, seed_chunk,
                              memory.ed25519_seeds, ED25519_SEED_SIZE,
                              current_run)                             { m[cursor++] = *seed_chunk.data; }
                                                                         m[cursor++] = 0x80000000;
            for (int i = cursor; i < 128/4-1; i++)                     { m[cursor++] = 0; }
                                                                         m[cursor++] = ED25519_SEED_SIZE*8;
        }

        sha512_transform_state(state, m, SHA512_OUTPUT_DATA, SHA512_DATA_MEMORY_LOCAL);

        // because ed25519 operates on individual chars
        // TODO: is this bswap really necessary?
        for (int i = 0; i < ED25519_SEED_SIZE/4; i++) { m[i] = __nv_bswap32(m[i]); }

        ge25519_p3 A;
        u8 *priv_key = (u8 *)m;
        u8 pub_key[ED25519_PUB_KEY_SIZE];

        priv_key[0] &= 248;
        priv_key[31] &= 63;
        priv_key[31] |= 64;

        ge25519_scalarmult_base(&A, priv_key);
        ge25519_p3_tobytes(pub_key, &A);

        for each_coal_tid(u32, pk_chunk, memory.public_keys, ED25519_PUB_KEY_SIZE, current_run) {
            *pk_chunk.data = *((uint32_t *)pub_key + pk_chunk.index);
        }

        //
        // MULTISIG PDA
        //

        PdaResult multisig_pda = find_multisig_pda(pub_key, multisig_bump_limit);

#if HASHWALL_INTERNAL
        for each_coal_tid(u32, pda_chunk, memory.multisig_pdas, SHA256_DIGEST_LENGTH, current_run) {
            *pda_chunk.data = multisig_pda.pda[pda_chunk.index];
        }
        for each_coal_tid(u32, bump, memory.multisig_bumps, sizeof(u32), current_run) {
            *bump.data = multisig_pda.bump;
        }
        for each_coal_tid(u32, multisig_is_off_curve, memory.multisig_is_off_curve, sizeof(u32), current_run) {
            *multisig_is_off_curve.data = !multisig_pda.is_on_curve;
        }
#endif

        if (!multisig_pda.is_on_curve) {
            //
            // VAULT PDA
            //

            PdaResult vault_pda = find_vault_pda((u8 *)multisig_pda.pda, 0, vault_bump_limit);

#if HASHWALL_INTERNAL
            for each_coal_tid(u32, pda_chunk, memory.vault_pdas, SHA256_DIGEST_LENGTH, current_run) {
                *pda_chunk.data = vault_pda.pda[pda_chunk.index];
            }
            for each_coal_tid(u32, bump, memory.vault_bumps, sizeof(u32), current_run) {
                *bump.data = vault_pda.bump;
            }
#endif

            if (!vault_pda.is_on_curve) {
                for each_coal_tid(u32, vault_is_off_curve, memory.vault_is_off_curve, sizeof(u32), current_run) {
                    *vault_is_off_curve.data = 1;
                    //*vault_is_off_curve.data = !vault_pda.is_on_curve;
                }

                //
                // base58
                //

                // TODO: 44/45/48 situation

                char b58[48] = {0};
                u32 b58_size = 45;
                b58enc(b58, &b58_size, (u8 *)vault_pda.pda, 32);

                for each_coal_tid(u32, it, memory.vault_pdas_b58, 48, current_run) {
                    *it.data = *((u32 *)b58 + it.index);
                }

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

        // TODO: BARRIER before next run
    }
}

typedef struct {
    f32 elapsed_time_ms;
    cudaError_t error;
} KernelResult;

KernelResult run_kernel(
    int grid_size, int block_size,
    DeviceMemory device_memory, DeviceMemory mirror,
    u64 runs_per_dispatch, int multisig_bump_limit, int vault_bump_limit,
    b32 should_log_time
) {
    KernelResult result = {0};

    cudaEvent_t event_start, event_stop;
    CUDA_CHECK(cudaEventCreate(&event_start));
    CUDA_CHECK(cudaEventCreate(&event_stop));
    {
        CUDA_CHECK(cudaEventRecord(event_start));
        {
            // TODO: it's probably more efficient to reset memory inside the main kernel
            // instead of launching a separate one
            reset_memory<<<grid_size, block_size>>>(device_memory, runs_per_dispatch);
            kernel<<<grid_size, block_size>>>(device_memory,
                                              runs_per_dispatch,
                                              multisig_bump_limit, vault_bump_limit);
        }
        CUDA_CHECK(cudaEventRecord(event_stop));
        CUDA_CHECK(cudaEventSynchronize(event_stop));
        CUDA_CHECK(cudaEventElapsedTime(&result.elapsed_time_ms, event_start, event_stop));
    }
    CUDA_CHECK(cudaEventDestroy(event_start));
    CUDA_CHECK(cudaEventDestroy(event_stop));

    result.error = cudaGetLastError();

    if (should_log_time) {
        printf("kernel<<<grid_size:%d, block_size:%d>>>(..., runs_per_dispatch:%ld, multisig_bump_limit:%d, vault_bump_limit:%d) exec time: %f ms\n",
                grid_size, block_size, runs_per_dispatch, multisig_bump_limit, vault_bump_limit,  result.elapsed_time_ms);
    }

#if HASHWALL_INTERNAL
    // TODO: these host tests could be overlapped with device execution and therefore
    // not be internal
    if (!result.error) {
        int total_threads = grid_size*block_size;

        CUDA_CHECK(cudaMemcpy(mirror.ed25519_seeds,         device_memory.ed25519_seeds,         runs_per_dispatch*total_threads*ED25519_SEED_SIZE,    cudaMemcpyDeviceToHost));
        CUDA_CHECK(cudaMemcpy(mirror.public_keys,           device_memory.public_keys,           runs_per_dispatch*total_threads*ED25519_PUB_KEY_SIZE, cudaMemcpyDeviceToHost));
        CUDA_CHECK(cudaMemcpy(mirror.multisig_pdas,         device_memory.multisig_pdas,         runs_per_dispatch*total_threads*SHA256_DIGEST_LENGTH, cudaMemcpyDeviceToHost));
        CUDA_CHECK(cudaMemcpy(mirror.multisig_bumps,        device_memory.multisig_bumps,        runs_per_dispatch*total_threads*sizeof(u32),          cudaMemcpyDeviceToHost));
        CUDA_CHECK(cudaMemcpy(mirror.multisig_is_off_curve, device_memory.multisig_is_off_curve, runs_per_dispatch*total_threads*sizeof(u32),          cudaMemcpyDeviceToHost));
        CUDA_CHECK(cudaMemcpy(mirror.vault_pdas,            device_memory.vault_pdas,            runs_per_dispatch*total_threads*SHA256_DIGEST_LENGTH, cudaMemcpyDeviceToHost));
        CUDA_CHECK(cudaMemcpy(mirror.vault_bumps,           device_memory.vault_bumps,           runs_per_dispatch*total_threads*sizeof(u32),          cudaMemcpyDeviceToHost));
        CUDA_CHECK(cudaMemcpy(mirror.vault_is_off_curve,    device_memory.vault_is_off_curve,    runs_per_dispatch*total_threads*sizeof(u32),          cudaMemcpyDeviceToHost));

        for (int current_run = 0; current_run < runs_per_dispatch; current_run += 1) {
            for (int tid = 0; tid < total_threads; tid += 1) {
                //
                // public keys
                //

                u8 seed[ED25519_SEED_SIZE] = {0};
                for each_strided_size_offset_by_size(u32, seed_chunk, mirror.ed25519_seeds, ED25519_SEED_SIZE, tid, total_threads, current_run) {
                    // NOTE: libsodium expects big-endian seed
                    *((u32 *)seed + seed_chunk.index) = bswap_u32(*seed_chunk.data);
                }

                u8 pk[ED25519_PUB_KEY_SIZE] = {0};
                u8 sk[ED25519_PRIV_KEY_SIZE] = {0};
                crypto_sign_ed25519_seed_keypair(pk, sk, seed);

                b32 pk_still_matches = 1;
                for each_strided_size_offset_by_size(u32, pk_chunk, mirror.public_keys, ED25519_PUB_KEY_SIZE, tid, total_threads, current_run) {
                    pk_still_matches = *pk_chunk.data == *((u32 *)pk + pk_chunk.index);
                }

                assert(pk_still_matches);

                //
                // multisig pdas
                //

                PdaResult pda_result = find_multisig_pda_host(pk, multisig_bump_limit);

                b32 multisig_pda_still_matches = 1;
                for each_strided_size_offset_by_size(u32, pda_chunk, mirror.multisig_pdas, SHA256_DIGEST_LENGTH, tid, total_threads, current_run) {
                    multisig_pda_still_matches = *pda_chunk.data == pda_result.pda[pda_chunk.index];
                }
                assert(multisig_pda_still_matches);

                u32 multisig_bump = 0;
                for each_strided_size_offset_by_size(u32, bump, mirror.multisig_bumps, sizeof(u32), tid, total_threads, current_run) {
                    multisig_bump = *bump.data;
                }
                assert(multisig_bump == pda_result.bump);

                u32 multisig_is_off_curve = 0;
                for each_strided_size_offset_by_size(u32, is_off_curve, mirror.multisig_is_off_curve, sizeof(u32), tid, total_threads, current_run) {
                    multisig_is_off_curve = *is_off_curve.data;
                }
                assert(multisig_is_off_curve == !pda_result.is_on_curve);

                //
                // vault pdas
                //

                if (multisig_is_off_curve) {
                    PdaResult vault_pda = find_vault_pda_host((u8 *)pda_result.pda, 0, vault_bump_limit);

                    b32 vault_pda_still_matches = 1;
                    for each_strided_size_offset_by_size(u32, pda_chunk, mirror.vault_pdas, SHA256_DIGEST_LENGTH, tid, total_threads, current_run) {
                        vault_pda_still_matches = *pda_chunk.data == vault_pda.pda[pda_chunk.index];
                    }
                    assert(vault_pda_still_matches);

                    u32 vault_bump = 0;
                    for each_strided_size_offset_by_size(u32, bump, mirror.vault_bumps, sizeof(u32), tid, total_threads, current_run) {
                        vault_bump = *bump.data;
                    }
                    assert(vault_bump == vault_pda.bump);

                    u32 vault_is_off_curve = 0;
                    for each_strided_size_offset_by_size(u32, is_off_curve, mirror.vault_is_off_curve, sizeof(u32), tid, total_threads, current_run) {
                        vault_is_off_curve = *is_off_curve.data;
                    }
                    assert(vault_is_off_curve == !vault_pda.is_on_curve);
                }
            }
        }
    }
#endif

    return result;
}

int main(int argc, char **argv) {
    //
    // host arena
    //

    Arena host_arena = {0};
    s64 host_arena_capacity = Gigabytes(2);
    arena_init(&host_arena, malloc(host_arena_capacity), host_arena_capacity);

    //
    // parse command line arguments
    //

    Flag_Parser_Options options = {0};
    options.program_name = string8_from_cstr(argv[0]);
    options.max_flags = 4;
    options.backing_arena = &host_arena;
    Flag_Parser parser = make_flag_parser(options);

    u64 runs_per_dispatch = 1; flag_parser_bind(&parser, FLAG_TYPE_U64,         &runs_per_dispatch, false, "runs", "amount of runs per kernel dispatch");
    String8 db_name = {0};     flag_parser_bind(&parser, FLAG_TYPE_STRING_VIEW, &db_name,           true,  "db",   "path to sqlite .db file");

    flag_parser_parse(&parser, argc, argv);

    print_string8(push_string8f(&host_arena, "CONFIGURATION\n"
                                             "database name:     %S\n"
                                             "runs per dispatch: %lu\n"
                                             "\n",
                                             db_name, runs_per_dispatch));

    //
    // init sqlite
    //

    // NOTE: this conversion is redundant since db_name string view points to
    // a command line argument which is already null-terminated. but it's
    // probably better to keep it in case db_name get trimmed or becomes a
    // string view of a larger string later
    char *db_name_cstr = cstr_from_string8(&host_arena, db_name);

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

    print_string8(push_string8f(&host_arena, "DEVICE PROPERTIES\n"
                                             "device name:           %s\n"
                                             "max threads per sm:    %d\n"
                                             "sm count:              %d\n"
                                             "total threads:         %d\n"
                                             "total global memory:   %zu MB\n"
                                             "total constant memory: %zu B\n"
                                             "\n",
                                             prop.name,
                                             max_threads_per_sm, sm_count, total_threads,
                                             prop.totalGlobalMem/1024/1024, prop.totalConstMem));

    //
    // init memory
    //

    // device memory and arena
    s64 device_buffer_size = Gigabytes(1);
    void *device_buffer;
    cudaMalloc(&device_buffer, device_buffer_size);
    cudaMemset(device_buffer, 0, device_buffer_size);

    Arena device_arena;
    arena_init(&device_arena, device_buffer, device_buffer_size);

    DeviceMemory device_memory = {0};
    device_memory.curand_states         =        arena_push_array_no_zero(&device_arena, total_threads*runs_per_dispatch,                      curandStateMRG32k3a);
    device_memory.ed25519_seeds         = (u32 *)arena_push_array_no_zero(&device_arena, total_threads*runs_per_dispatch*ED25519_SEED_SIZE,    u8);
    device_memory.public_keys           = (u32 *)arena_push_array_no_zero(&device_arena, total_threads*runs_per_dispatch*ED25519_PUB_KEY_SIZE, u8);
#if HASHWALL_INTERNAL
    device_memory.multisig_pdas         = (u32 *)arena_push_array_no_zero(&device_arena, total_threads*runs_per_dispatch*SHA256_DIGEST_LENGTH, u8);
    device_memory.multisig_bumps        =        arena_push_array_no_zero(&device_arena, total_threads*runs_per_dispatch,                      u32);
    device_memory.multisig_is_off_curve =        arena_push_array_no_zero(&device_arena, total_threads*runs_per_dispatch,                      u32);
    device_memory.vault_pdas            = (u32 *)arena_push_array_no_zero(&device_arena, total_threads*runs_per_dispatch*SHA256_DIGEST_LENGTH, u8);
    device_memory.vault_bumps           =        arena_push_array_no_zero(&device_arena, total_threads*runs_per_dispatch,                      u32);
#endif
    device_memory.vault_is_off_curve    =        arena_push_array_no_zero(&device_arena, total_threads*runs_per_dispatch,                      u32);
    device_memory.vault_pdas_b58        = (u32 *)arena_push_array_no_zero(&device_arena, total_threads*runs_per_dispatch*48,                   u8);
    device_memory.found                 =        arena_push_array_no_zero(&device_arena, total_threads*runs_per_dispatch,                      u32);

    // device memory host mirror
    Arena mirror_arena = arena_make_subarena(&host_arena, device_buffer_size, 256);

    DeviceMemory mirror = {0};
    copy_device_memory(&mirror, &mirror_arena, &device_memory, &device_arena);

    // global constant memory
    string8_copy_to_symbol(&device_arena, &d_seed_prefix,   &h_seed_prefix);
    string8_copy_to_symbol(&device_arena, &d_seed_multisig, &h_seed_multisig);
    string8_copy_to_symbol(&device_arena, &d_seed_vault,    &h_seed_vault);
    string8_copy_to_symbol(&device_arena, &d_pda_postfix,   &h_pda_postfix);

    // TODO: remove later
    assert((u8 *)mirror.curand_states         - (u8 *)mirror_arena.memory == (u8 *)device_memory.curand_states         - (u8 *)device_arena.memory);
    assert((u8 *)mirror.ed25519_seeds         - (u8 *)mirror_arena.memory == (u8 *)device_memory.ed25519_seeds         - (u8 *)device_arena.memory);
    assert((u8 *)mirror.public_keys           - (u8 *)mirror_arena.memory == (u8 *)device_memory.public_keys           - (u8 *)device_arena.memory);
#if HASHWALL_INTERNAL
    assert((u8 *)mirror.multisig_pdas         - (u8 *)mirror_arena.memory == (u8 *)device_memory.multisig_pdas         - (u8 *)device_arena.memory);
    assert((u8 *)mirror.multisig_bumps        - (u8 *)mirror_arena.memory == (u8 *)device_memory.multisig_bumps        - (u8 *)device_arena.memory);
    assert((u8 *)mirror.multisig_is_off_curve - (u8 *)mirror_arena.memory == (u8 *)device_memory.multisig_is_off_curve - (u8 *)device_arena.memory);
    assert((u8 *)mirror.vault_pdas            - (u8 *)mirror_arena.memory == (u8 *)device_memory.vault_pdas            - (u8 *)device_arena.memory);
    assert((u8 *)mirror.vault_bumps           - (u8 *)mirror_arena.memory == (u8 *)device_memory.vault_bumps           - (u8 *)device_arena.memory);
#endif
    assert((u8 *)mirror.vault_is_off_curve    - (u8 *)mirror_arena.memory == (u8 *)device_memory.vault_is_off_curve    - (u8 *)device_arena.memory);
    assert((u8 *)mirror.vault_pdas_b58        - (u8 *)mirror_arena.memory == (u8 *)device_memory.vault_pdas_b58        - (u8 *)device_arena.memory);
    assert((u8 *)mirror.found                 - (u8 *)mirror_arena.memory == (u8 *)device_memory.found                 - (u8 *)device_arena.memory);

    // wordlist arena
    Arena wordlist_arena = arena_make_subarena(&host_arena, WORDLIST_SIZE, 256);

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
    // find optimal kernel configuration
    //

    reload_wordlist(&wordlist_arena);

    int best_block_size = 0;
    int best_multisig_bump_limit = 0;
    int best_vault_bump_limit = 0;
    float best_average_ms = 0;
    float best_points_per_second = 0;

    for (int block_size = 256; block_size <= 512; block_size *= 2) {
        int blocks_per_sm = max_threads_per_sm / block_size;
        int grid_size = blocks_per_sm * sm_count;

        for (int multisig_bump_limit = 3; multisig_bump_limit <= 3; multisig_bump_limit += 1) {
            for (int vault_bump_limit = 3; vault_bump_limit <= 3; vault_bump_limit += 1) {
                float total_ms = 0;
                int total_on_curve_points = 0;

                int runs = 10;
                assert(runs > 1);

                cudaError_t err = cudaErrorUnknown;

                for (int run = 0; run < runs; run += 1) {
                    KernelResult result = run_kernel(grid_size, block_size,
                                                     device_memory, mirror,
                                                     runs_per_dispatch,
                                                     multisig_bump_limit, vault_bump_limit,
                                                     false);

                    err = result.error;
                    if (!err) {
                        // ignore the warm-up run
                        if (run > 0) {
                            total_ms += result.elapsed_time_ms;

                            CUDA_CHECK(cudaMemcpy(
                                mirror.vault_is_off_curve, device_memory.vault_is_off_curve,
                                runs_per_dispatch*total_threads*sizeof(u32),
                                cudaMemcpyDeviceToHost
                            ));

                            for (int current_run = 0; current_run < runs_per_dispatch; current_run += 1) {
                                for (int tid = 0; tid < total_threads; tid += 1) {
                                    for each_strided_count(u32, vault_is_off_curve, mirror.vault_is_off_curve, 1, tid, total_threads, current_run) {
                                        if (*vault_is_off_curve.data) {
                                            // NOTE: value other than 1 means it was corrupted by some other data
                                            assert(*vault_is_off_curve.data == (u32)1);

                                            total_on_curve_points += 1;
                                        }
                                    }
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

                    printf("kernel<<<grid_size:%d, block_size:%d>>>(..., runs_per_dispatch:%ld, multisig_bump_limit:%d, vault_bump_limit:%d) average exec time: %f ms (%f points/s)\n", grid_size, block_size, runs_per_dispatch, multisig_bump_limit, vault_bump_limit, average_ms, points_per_second);
                }
            }
        }
    }

    print_string8(push_string8f(&host_arena, "\n"
                                             "OPTIMAL CONFIGURATION\n"
                                             "block size:          %d\n"
                                             "multisig bump limit: %d\n"
                                             "vault bump limit:    %d\n"
                                             "-----------------------\n"
                                             "average ms:          %f\n"
                                             "points per second:   %f\n"
                                             "\n",
                                             best_block_size, best_multisig_bump_limit, best_vault_bump_limit,
                                             best_average_ms, best_points_per_second));

    //
    // main loop
    //

    int block_size = best_block_size;
    int blocks_per_sm = max_threads_per_sm / block_size;
    int grid_size = blocks_per_sm * sm_count;

    Arena cycle_arena = arena_make_subarena(&host_arena, Megabytes(100), 256);

    int found = 0;
    int cycles = 0;
#if 1
    while (!found)
#endif
    {
        arena_free(&cycle_arena);
#if 1
        if (cycles % 100 == 0) {
            cycles = 0;
            reload_wordlist(&wordlist_arena);
        }
        cycles += 1;
#endif

        run_kernel(grid_size, block_size,
                   device_memory, mirror,
                   runs_per_dispatch,
                   best_multisig_bump_limit, best_vault_bump_limit,
                   true);
        CUDA_CHECK(cudaDeviceSynchronize());

        CUDA_CHECK(cudaMemcpy(mirror.found, device_memory.found,
                              runs_per_dispatch*total_threads*sizeof(u32),
                              cudaMemcpyDeviceToHost));

        for (int current_run = 0; current_run < runs_per_dispatch; current_run += 1) {
            for (int tid = 0; tid < total_threads; tid += 1) {
                for each_coal_tid_host(u32, found, mirror.found, sizeof(u32), current_run) {
                    if (*found.data) {
                        // NOTE: value other than 1 means it was corrupted by some other data
                        assert(*found.data == (u32)1);

                        CUDA_CHECK(cudaMemcpy(mirror.ed25519_seeds,  device_memory.ed25519_seeds,  total_threads*runs_per_dispatch*ED25519_SEED_SIZE*sizeof(u32),    cudaMemcpyDeviceToHost));
                        CUDA_CHECK(cudaMemcpy(mirror.public_keys,    device_memory.public_keys,    total_threads*runs_per_dispatch*ED25519_PUB_KEY_SIZE*sizeof(u32), cudaMemcpyDeviceToHost));
                        CUDA_CHECK(cudaMemcpy(mirror.vault_pdas_b58, device_memory.vault_pdas_b58, total_threads*runs_per_dispatch*48,                               cudaMemcpyDeviceToHost));

                        List keypair_list = {0};
                        for each_coal_tid_host(u32, seed, mirror.ed25519_seeds, ED25519_SEED_SIZE, current_run) {
                            u32 c = *seed.data;
                            // TODO: format_string8 seems like overkill for a simple int to string conversion
                            list_push(&cycle_arena, &keypair_list, String8, push_string8f(&cycle_arena, "%d", (u8)(c >> 24)));
                            list_push(&cycle_arena, &keypair_list, String8, push_string8f(&cycle_arena, "%d", (u8)(c >> 16)));
                            list_push(&cycle_arena, &keypair_list, String8, push_string8f(&cycle_arena, "%d", (u8)(c >> 8)));
                            list_push(&cycle_arena, &keypair_list, String8, push_string8f(&cycle_arena, "%d", (u8)(c)));
                        }

                        for each_coal_tid_host(u32, key, mirror.public_keys, ED25519_PUB_KEY_SIZE, current_run) {
                            u32 c = *key.data;
                            list_push(&cycle_arena, &keypair_list, String8, push_string8f(&cycle_arena, "%d", (u8)(c)));
                            list_push(&cycle_arena, &keypair_list, String8, push_string8f(&cycle_arena, "%d", (u8)(c >> 8)));
                            list_push(&cycle_arena, &keypair_list, String8, push_string8f(&cycle_arena, "%d", (u8)(c >> 16)));
                            list_push(&cycle_arena, &keypair_list, String8, push_string8f(&cycle_arena, "%d", (u8)(c >> 24)));
                        }

                        String8 keypair_string = push_string8f(&cycle_arena, "[%S]", string8_from_list(&cycle_arena, &keypair_list, str8lit(",")));

                        char pda[48] = {0};
                        for each_coal_tid_host(u32, item, mirror.vault_pdas_b58, 48, current_run) {
                            *((u32 *)pda + item.index) = *item.data;
                        }

                        print_string8(push_string8f(&cycle_arena, "found at (tid=%d, current_run=%d)\n"
                                                                   "keypair: %S\n"
                                                                   "vault:   %.*s\n",
                                                                   tid, current_run,
                                                                   keypair_string,
                                                                   48, pda));

                        save_found_vault(db, keypair_string, pda);
                    }
                }
            }
        }
    }

    return 0;
}
