#ifndef X16RV2_H
#define X16RV2_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

void x16rv2_hash(const char* input, char* output, uint32_t len);

#ifdef __cplusplus
}
#endif

#endif