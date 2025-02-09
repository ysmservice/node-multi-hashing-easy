#ifndef EQUIHASH_H
#define EQUIHASH_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdlib.h>

typedef struct {
    int32_t N;
    int32_t K;
    const char* personalization;
} EquihashParams;

void equihash_hash(const char* input, char* output, uint32_t len, const EquihashParams* params);

#ifdef __cplusplus
}
#endif

#endif // EQUIHASH_H