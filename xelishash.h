#ifndef XELISHASH_H
#define XELISHASH_H

#include <stdint.h>
#include <stddef.h>
#include <wmmintrin.h> // AES-NI

#ifdef __cplusplus
extern "C" {
#endif

#define XELIS_INPUT_LEN (112)
#define XELIS_MEMSIZE (429 * 128)
#define XELIS_ITERS (3)
#define XELIS_HASHSIZE (32)

// Legacy v1 hash function
void xelishash_hash(const char* input, char* output, uint32_t len);

// V2 hash function and its components
void xelishash_v2(const char* input, char* output, uint32_t len);
void xelis_stage1(const uint8_t *input, size_t input_len, uint8_t *scratch_pad);
void xelis_stage3(uint64_t *scratch);
void aes_single_round(uint8_t *block, const uint8_t *key);

// Utility functions
static inline uint64_t xelis_rotr64(uint64_t x, uint32_t n);
static inline uint64_t xelis_rotl64(uint64_t x, uint32_t n);
uint64_t xelis_isqrt(uint64_t n);

#ifdef __cplusplus
}
#endif

#endif // XELISHASH_H