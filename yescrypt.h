
#ifndef YESCRYPT_H
#define YESCRYPT_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

void yescrypt_hash(const char* input, char* output, uint32_t len);

#ifdef __cplusplus
}
#endif

#endif // YESCRYPT_H