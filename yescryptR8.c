#include "yescryptR8.h"
#include "yescrypt.h"

void yescryptR8_hash(const char* input, char* output, uint32_t len) {
    yescrypt_hash_sp(input, output, len, 2048, 8, 1);
}