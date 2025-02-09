#ifndef ETHASH_H
#define ETHASH_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ethash_params {
    unsigned epochs;
    unsigned epoch_length;
    unsigned cache_size;
    unsigned dag_size;
} ethash_params;

bool ethash_init_epoch(uint32_t epoch_number);
void ethash_get_epoch_data(uint32_t epoch_number, uint8_t* cache, uint8_t* dag);
void ethash_hash(const char* input, char* output, uint32_t len, uint32_t epoch_number);
bool ethash_verify(const char* header_hash, const char* mix_hash, uint64_t nonce, uint32_t epoch_number);

#ifdef __cplusplus
}
#endif

#endif