#ifndef HEAVYHASH_H
#define HEAVYHASH_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

void heavyhash_hash(const char* input, char* output, uint32_t len);

#ifdef __cplusplus
}
#endif

#endif