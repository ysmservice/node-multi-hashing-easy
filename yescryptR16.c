#include "yescryptR16.h"
#include "yescrypt.h"

void yescryptR16_hash(const char* input, char* output, uint32_t len) {
    yescrypt_hash_sp(input, output, len, 2048, 16, 1);
}