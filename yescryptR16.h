#ifndef YESCRYPTR16_H
#define YESCRYPTR16_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

void yescryptR16_hash(const char* input, char* output, uint32_t len);

#ifdef __cplusplus
}
#endif

#endif