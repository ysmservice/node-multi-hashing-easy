#ifndef MEOWPOW_H
#define MEOWPOW_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

void meowpow_hash(const char* input, char* output, uint32_t height, int *retval);

#ifdef __cplusplus
}
#endif

#endif