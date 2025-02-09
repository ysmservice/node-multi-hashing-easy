#ifndef VERTHASH_H
#define VERTHASH_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

void verthash_init();
void verthash_hash(const char* input, char* output, uint32_t len);

#ifdef __cplusplus
}
#endif

#endif