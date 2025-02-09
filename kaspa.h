#ifndef KASPA_H
#define KASPA_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

void kaspa_hash(const char* input, char* output, uint32_t len);
void kaspa_pow(const char* input, char* output, uint32_t len);

#ifdef __cplusplus
}
#endif

#endif // KASPA_H