#ifndef PROGPOW_H
#define PROGPOW_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

// ProgPowのパラメータ構造体
typedef struct {
    uint32_t epoch_length;
    uint64_t dag_size;
    uint32_t cache_size;
} progpow_params;

void progpow_hash(const char* input, char* output, uint32_t len, const progpow_params* params);
bool progpow_init_epoch(uint32_t epoch_number);

#ifdef __cplusplus
}
#endif

#endif