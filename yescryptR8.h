#ifndef YESCRYPTR8_H
#define YESCRYPTR8_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

void yescryptR8_hash(const char* input, char* output, uint32_t len);

#ifdef __cplusplus
}
#endif

#endif