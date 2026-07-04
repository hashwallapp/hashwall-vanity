#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#define STB_SPRINTF_IMPLEMENTATION
#include "third_party/stb_sprintf.h"
#include "third_party/libsodium/sodium.h"

typedef uint8_t  u8;
typedef uint32_t u32;
typedef uint64_t u64;

static char *seed_prefix   = "multisig";
static char *seed_multisig = "multisig";
static char *seed_vault    = "vault";
static char *pda_postfix   = "ProgramDerivedAddress";

#define MULTISIG_SEEDS_SIZE (8 + 8 + 32 + 1 + 32 + 21) // "multisig" + "multisig" + pk + bump + program_id + "ProgramDerivedAddress"
#define VAULT_SEEDS_SIZE (8 + 32 + 5 + 1 + 1+ 32 + 21) // "multisig" + multisig_pda + "vault" + index + bump + program_id + "ProgramDerivedAddress"

#define PROGRAM_ID "0681C4CE47E22368B8B1555EC887AF092EFC7EFBB66CA3F52FBF68D4AC9CB7A8" // SQDS4ep65T869zMMBKyuUq6aD6EgTu8psMjkvj52pCf

u8 *debug_hex_string_to_byte_array(char *hex, size_t size) {
    u8 *result = (u8 *)malloc(size);
    for (int i = 0; i < size; i++) {
        char digit[3];
        stbsp_snprintf(digit, 3, "%s", hex + i*2);
        result[i] = strtoul(digit, 0, 16) & 0xFF;
    }
    return result;
}

u8 *debug_build_vault_seeds(u8 *multisig_pda, u8 index, u8 bump, u8 *program_id) {
    u8 *seeds = (u8 *)malloc(VAULT_SEEDS_SIZE);
    *seeds = 0;

    int cursor = 0;

    for (int i = 0; i < strlen(seed_prefix); i++) { seeds[cursor++] = seed_prefix[i]; }
    for (int i = 0; i < 32; i++)                  { seeds[cursor++] = multisig_pda[i]; }
    for (int i = 0; i < strlen(seed_vault); i++)  { seeds[cursor++] = seed_vault[i]; }
                                                    seeds[cursor++] = index;
                                                    seeds[cursor++] = bump;
    for (int i = 0; i < 32; i++)                  { seeds[cursor++] = program_id[i]; }
    for (int i = 0; i < strlen(pda_postfix); i++) { seeds[cursor++] = pda_postfix[i]; }

    assert(cursor == VAULT_SEEDS_SIZE);

    return seeds;
}

u8 *debug_build_multisig_seeds(u8 *pk, u8 bump, u8 *program_id) {
    u8 *seeds = (u8 *)malloc(MULTISIG_SEEDS_SIZE);
    *seeds = 0;

    int cursor = 0;

    for (int i = 0; i < strlen(seed_prefix); i++)   { seeds[cursor++] = seed_prefix[i]; }
    for (int i = 0; i < strlen(seed_multisig); i++) { seeds[cursor++] = seed_multisig[i]; }
    for (int i = 0; i < 32; i++)                    { seeds[cursor++] = pk[i]; }
                                                      seeds[cursor++] = bump;
    for (int i = 0; i < 32; i++)                    { seeds[cursor++] = program_id[i]; }
    for (int i = 0; i < strlen(pda_postfix); i++)   { seeds[cursor++] = pda_postfix[i]; }

    assert(cursor == MULTISIG_SEEDS_SIZE);

    return seeds;
}

typedef struct {
    u8 bytes[32];
    u8 bump;
} PdaResult;

PdaResult debug_get_vault_pda(u8 multisig_pda[32], u8 *program_id) {
    int is_on_curve = 1;
    int bump = 256;
    u8 hash[32];
    while (is_on_curve) {
        bump -= 1;
        u8 *seeds = debug_build_vault_seeds(multisig_pda, 0, bump, program_id);
        {
            int hash_error = crypto_hash_sha256(hash, seeds, VAULT_SEEDS_SIZE);
            assert(!hash_error);
            is_on_curve = crypto_core_ed25519_is_valid_point(hash);
        }
        free(seeds);
    }
    assert(!is_on_curve);

    PdaResult result = {0};
    result.bump = bump;
    for (int i = 0; i < 32; i++) { result.bytes[i] = hash[i]; }
    return result;
}

PdaResult debug_get_multisig_pda(u8 pk[32], u8 *program_id) {
    int is_on_curve = 1;
    int bump = 256;
    u8 hash[32];
    while (is_on_curve) {
        bump -= 1;
        u8 *seeds = debug_build_multisig_seeds(pk, bump, program_id);
        {
            int hash_error = crypto_hash_sha256(hash, seeds, MULTISIG_SEEDS_SIZE);
            assert(!hash_error);
            is_on_curve = crypto_core_ed25519_is_valid_point(hash);
        }
        free(seeds);
    }
    assert(!is_on_curve);

    PdaResult result = {0};
    result.bump = bump;
    for (int i = 0; i < 32; i++) { result.bytes[i] = hash[i]; }
    return result;
}

int main(int argc, char **argv) {
    u8 *program_id = debug_hex_string_to_byte_array(PROGRAM_ID, 32);
    int program_id_length = strlen(program_id);

    printf("u8 program_id[%d] = { ", program_id_length);
    for (int i = 0; i < program_id_length - 1; i++) {
        printf("%d, ", program_id[i]);
    }
    printf("%d };\n", program_id[program_id_length - 1]);

#if 1
    u8 sk[64];
    u8 pk[32];
    crypto_sign_ed25519_keypair(pk, sk);

    u8 seed[32];
    crypto_sign_ed25519_sk_to_seed(seed, sk);
#else
    u8 seed[32] = { 63, 39, 252, 73, 111, 188, 218, 50, 91, 91, 38, 2, 194, 179, 84, 172, 210, 93, 64, 21, 243, 244, 63, 31, 226, 20, 112, 182, 199, 150, 155, 0 };
    u8 pk[32] = { 68, 147, 139, 175, 185, 114, 9, 6, 59, 99, 81, 68, 135, 104, 50, 82, 149, 52, 119, 225, 132, 185, 147, 54, 12, 99, 221, 100, 43, 169, 26, 113 };
#endif

    PdaResult multisig_pda = debug_get_multisig_pda(pk, program_id);
    printf("multisig pda: "); for (int i = 0; i < 32; i++) { printf("%02x", multisig_pda.bytes[i]); } printf("\n");
    printf("multisig bump: %d\n", multisig_pda.bump);

    PdaResult vault_pda = debug_get_vault_pda(multisig_pda.bytes, program_id);
    printf("vault pda: "); for (int i = 0; i < 32; i++) { printf("%02x", vault_pda.bytes[i]); } printf("\n");
    printf("vault bump: %d\n", vault_pda.bump);

    printf("seed_keypair: [");
    for (int i = 0; i < 32; i++) { printf("%d,", seed[i]); }
    for (int i = 0; i < 31; i++) { printf("%d,", pk[i]); }
    printf("%d]", pk[31]);
    printf("\n");

    return 0;
}
