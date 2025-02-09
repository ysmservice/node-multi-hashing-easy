#ifndef ZANO_H
#define ZANO_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

void zano_hash(const char* input, char* output, uint32_t len);
void zano_pow(const char* input, char* output, uint32_t len, const char* seed_hash);

#ifdef __cplusplus
}
#endif

#endif // ZANO_H