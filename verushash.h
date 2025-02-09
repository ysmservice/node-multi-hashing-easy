#ifndef VERUSHASH_H
#define VERUSHASH_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

void verushash_hash(const char* input, char* output, uint32_t len);

#ifdef __cplusplus
}
#endif

#endif