#ifndef GHOSTRIDER_H
#define GHOSTRIDER_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

void ghostrider_hash(const char* input, char* output, uint32_t len);

#ifdef __cplusplus
}
#endif

#endif