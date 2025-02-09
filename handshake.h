#ifndef HANDSHAKE_H
#define HANDSHAKE_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

void handshake_hash(const char* input, char* output, uint32_t len);

#ifdef __cplusplus
}
#endif

#endif // HANDSHAKE_H