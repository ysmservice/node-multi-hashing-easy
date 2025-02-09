#include "yespowerr16.h"
#include "yespower.h"
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

void yespowerR16_hash(const char* input, char* output, uint32_t len)
{
    yespower_params_t params = {
        .version = YESPOWER_1_0,
        .N = 2048,
        .r = 16,
        .pers = (const uint8_t *)"CPUpower: The number of CPU working or available for proof-of-work mining",
        .perslen = 73
    };
    
    yespower_tls((const uint8_t *)input, len, &params, (yespower_binary_t *)output);
}