#ifndef YESCRYPTR32_H
#define YESCRYPTR32_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

void yescryptR32_hash(const char* input, char* output, uint32_t len);

#ifdef __cplusplus
}
#endif

#endif