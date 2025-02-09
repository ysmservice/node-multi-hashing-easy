#ifndef NEXA_H
#define NEXA_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

void nexa_hash(const char* input, char* output, uint32_t len);
void nexa_verify(const char* header, const char* coinbase, const char* merkle_root, uint32_t nonce, char* output);

#ifdef __cplusplus
}
#endif

#endif // NEXA_H