#ifndef YESPOWER_H
#define YESPOWER_H

#include <stdint.h>

/*
 * yespower parameters combined into one struct for convenience.
 */
typedef struct {
    int version;
    uint32_t N;
    uint32_t r;
    const uint8_t *pers;
    size_t perslen;
} yespower_params_t;

#define YESPOWER_1_0 1

typedef struct {
    unsigned char uc[32];
} yespower_binary_t;

/**
 * yespower_tls(local, src, srclen, params, dst):
 * Compute yespower(src[0 .. srclen - 1], params), storing the result in dst.
 *
 * Return 0 on success; or -1 on error.
 */
int yespower_tls(const uint8_t *src, size_t srclen,
    const yespower_params_t *params, yespower_binary_t *dst);

#endif /* YESPOWER_H */