#ifndef BEAMHASH_H
#define BEAMHASH_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

void beamhash_hash(const char* input, char* output, uint32_t len);

#ifdef __cplusplus
}
#endif

#endif