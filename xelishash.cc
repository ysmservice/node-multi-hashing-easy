#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include "xelishash.h"
#include "blake3/blake3.h"
#include "chacha20/chacha20.h"

#define INPUT_LEN (112)
#define MEMSIZE (429 * 128)
#define ITERS (3)
#define HASHSIZE (32)
#define CHUNK_SIZE (32)
#define NONCE_SIZE (12)
#define OUTPUT_SIZE (MEMSIZE * 8)
#define CHUNKS (4)
#define BUFSIZE (MEMSIZE / 2)
#define KEY "xelishash-pow-v2"

static inline uint64_t combine_uint64(uint64_t high, uint64_t low) {
    return ((__uint128_t)high << 64) | low;
}

static inline void uint64_to_le_bytes(uint64_t value, uint8_t *bytes) {
    for (int i = 0; i < 8; i++) {
        bytes[i] = value & 0xFF;
        value >>= 8;
    }
}

static inline uint64_t le_bytes_to_uint64(const uint8_t *bytes) {
    uint64_t value = 0;
    for (int i = 7; i >= 0; i--)
        value = (value << 8) | bytes[i];
    return value;
}

static inline uint64_t ROTR(uint64_t x, uint32_t r) {
    return (x >> r) | (x << (64 - r));
}

static inline uint64_t ROTL(uint64_t x, uint32_t r) {
    return (x << r) | (x >> (64 - r));
}

static inline void aes_single_round(uint8_t *block, const uint8_t *key) {
    __m128i block_vec = _mm_loadu_si128((const __m128i *)block);
    __m128i key_vec = _mm_loadu_si128((const __m128i *)key);
    
    // Perform single AES encryption round
    block_vec = _mm_aesenc_si128(block_vec, key_vec);
    
    _mm_storeu_si128((__m128i *)block, block_vec);
}

uint64_t isqrt(uint64_t n) {
    if (n < 2) return n;
    
    uint64_t x = n;
    uint64_t result = 0;
    uint64_t bit = (uint64_t)1 << 62;
    
    while (bit > x) bit >>= 2;
    
    while (bit != 0) {
        if (x >= result + bit) {
            x -= result + bit;
            result = (result >> 1) + bit;
        } else {
            result >>= 1;
        }
        bit >>= 2;
    }
    
    return result;
}

static void stage1(const uint8_t *input, size_t input_len, uint8_t scratch_pad[OUTPUT_SIZE]) {
    uint8_t key[CHUNK_SIZE * CHUNKS] = {0};
    uint8_t input_hash[HASHSIZE];
    uint8_t buffer[CHUNK_SIZE * 2];
    memcpy(key, input, input_len);

    blake3_hasher hasher;
    blake3_hasher_init(&hasher);
    blake3_hasher_update(&hasher, input, input_len);
    blake3_hasher_finalize(&hasher, buffer, HASHSIZE);
    
    uint8_t *t = scratch_pad;
    
    memcpy(buffer + CHUNK_SIZE, key + 0 * CHUNK_SIZE, CHUNK_SIZE);
    blake3_hasher_init(&hasher);
    blake3_hasher_update(&hasher, buffer, CHUNK_SIZE * 2);
    blake3_hasher_finalize(&hasher, input_hash, HASHSIZE);
    chacha20_encrypt(input_hash, buffer, NULL, t, OUTPUT_SIZE / CHUNKS);
    
    t += OUTPUT_SIZE / CHUNKS;
    memcpy(buffer, input_hash, CHUNK_SIZE);
    memcpy(buffer + CHUNK_SIZE, key + 1 * CHUNK_SIZE, CHUNK_SIZE);
    blake3_hasher_init(&hasher);
    blake3_hasher_update(&hasher, buffer, CHUNK_SIZE * 2);
    blake3_hasher_finalize(&hasher, input_hash, HASHSIZE);
    chacha20_encrypt(input_hash, t - NONCE_SIZE, NULL, t, OUTPUT_SIZE / CHUNKS);
    
    t += OUTPUT_SIZE / CHUNKS;
    memcpy(buffer, input_hash, CHUNK_SIZE);
    memcpy(buffer + CHUNK_SIZE, key + 2 * CHUNK_SIZE, CHUNK_SIZE);
    blake3_hasher_init(&hasher);
    blake3_hasher_update(&hasher, buffer, CHUNK_SIZE * 2);
    blake3_hasher_finalize(&hasher, input_hash, HASHSIZE);
    chacha20_encrypt(input_hash, t - NONCE_SIZE, NULL, t, OUTPUT_SIZE / CHUNKS);
    
    t += OUTPUT_SIZE / CHUNKS;
    memcpy(buffer, input_hash, CHUNK_SIZE);
    memcpy(buffer + CHUNK_SIZE, key + 3 * CHUNK_SIZE, CHUNK_SIZE);
    blake3_hasher_init(&hasher);
    blake3_hasher_update(&hasher, buffer, CHUNK_SIZE * 2);
    blake3_hasher_finalize(&hasher, input_hash, HASHSIZE);
    chacha20_encrypt(input_hash, t - NONCE_SIZE, NULL, t, OUTPUT_SIZE / CHUNKS);
}

static void stage3(uint64_t *scratch) {
    uint64_t *mem_buffer_a = scratch;
    uint64_t *mem_buffer_b = &scratch[BUFSIZE];
    
    uint64_t addr_a = mem_buffer_b[BUFSIZE - 1];
    uint64_t addr_b = mem_buffer_a[BUFSIZE - 1] >> 32;
    uint32_t r = 0;
    
    for (uint32_t i = 0; i < ITERS; i++) {
        uint64_t mem_a = mem_buffer_a[addr_a % BUFSIZE];
        uint64_t mem_b = mem_buffer_b[addr_b % BUFSIZE];
        
        uint8_t block[16];
        uint64_to_le_bytes(mem_b, block);
        uint64_to_le_bytes(mem_a, block + 8);
        aes_single_round(block, (const uint8_t*)KEY);
        
        uint64_t hash1 = le_bytes_to_uint64(block);
        uint64_t hash2 = mem_a ^ mem_b;
        uint64_t result = ~(hash1 ^ hash2);
        
        for (uint32_t j = 0; j < BUFSIZE; j++) {
            uint64_t a = mem_buffer_a[result % BUFSIZE];
            uint64_t b = mem_buffer_b[~ROTR(result, r) % BUFSIZE];
            uint64_t c = (r < BUFSIZE) ? mem_buffer_a[r] : mem_buffer_b[r - BUFSIZE];
            r = (r < MEMSIZE - 1) ? r + 1 : 0;
            
            uint64_t v;
            __uint128_t t1, t2;
            switch (ROTL(result, (uint32_t)c) & 0xf) {
                case 0: v = ROTL(c, i * j) ^ b; break;
                case 1: v = ROTR(c, i * j) ^ a; break;
                case 2: v = a ^ b ^ c; break;
                case 3: v = ((a + b) * c); break;
                case 4: v = ((b - c) * a); break;
                case 5: v = (c - a + b); break;
                case 6: v = (a - b + c); break;
                case 7: v = (b * c + a); break;
                case 8: v = (c * a + b); break;
                case 9: v = (a * b * c); break;
                case 10: {
                    t1 = combine_uint64(a, b);
                    uint64_t t2 = c | 1;
                    v = t1 % t2;
                } break;
                case 11: {
                    t1 = combine_uint64(b, c);
                    t2 = combine_uint64(ROTL(result, r), a | 2);
                    v = (t2 > t1) ? c : t1 % t2;
                } break;
                case 12: {
                    v = (c / (b | 4)) * a;
                } break;
                case 13: {
                    t1 = combine_uint64(ROTL(result, r), b);
                    t2 = combine_uint64(a, c | 8);
                    v = (t1 > t2) ? t1 / t2 : a ^ b;
                } break;
                case 14: {
                    t1 = combine_uint64(b, a);
                    uint64_t t2 = c;
                    v = (t1 * t2) >> 64;
                } break;
                case 15: {
                    t1 = combine_uint64(a, c);
                    t2 = combine_uint64(ROTR(result, r), b);
                    v = (t1 * t2) >> 64;
                } break;
            }
            result = ROTL(result ^ v, 1);
            
            uint64_t t = mem_buffer_a[BUFSIZE - j - 1] ^ result;
            mem_buffer_a[BUFSIZE - j - 1] = t;
            mem_buffer_b[j] ^= ROTR(t, result);
        }
        addr_a = result;
        addr_b = isqrt(result);
    }
}

void xelishash_v2(const char* input, char* output, uint32_t len) {
    uint64_t *scratch = (uint64_t *)calloc(MEMSIZE, sizeof(uint64_t));
    if (!scratch) return;
    
    stage1((const uint8_t*)input, len, (uint8_t*)scratch);
    stage3(scratch);
    
    blake3_hasher hasher;
    blake3_hasher_init(&hasher);
    blake3_hasher_update(&hasher, (uint8_t*)scratch, OUTPUT_SIZE);
    blake3_hasher_finalize(&hasher, (uint8_t*)output, HASHSIZE);
    
    free(scratch);
}

// 旧バージョンのハッシュ関数
void xelishash_hash(const char* input, char* output, uint32_t len) {
    // V1は単純にBLAKE3を2回適用
    blake3_hasher hasher;
    uint8_t temp_hash[32];

    // 第1ステージ
    blake3_hasher_init(&hasher);
    blake3_hasher_update(&hasher, input, len);
    blake3_hasher_finalize(&hasher, temp_hash, 32);

    // 第2ステージ
    blake3_hasher_init(&hasher);
    blake3_hasher_update(&hasher, temp_hash, 32);
    blake3_hasher_finalize(&hasher, (uint8_t*)output, 32);
}

#include <node.h>
#include <node_buffer.h>
#include <v8.h>

void init(v8::Handle<v8::Object> exports) {
    NODE_SET_METHOD(exports, "xelishash", method_v1);
    NODE_SET_METHOD(exports, "xelishash_v2", method_v2);
}

void method_v1(const v8::FunctionCallbackInfo<v8::Value>& args) {
    v8::Isolate* isolate = args.GetIsolate();
    
    if (args.Length() < 1) {
        isolate->ThrowException(v8::Exception::TypeError(
            v8::String::NewFromUtf8(isolate, "Wrong number of arguments")));
        return;
    }
    
    v8::Local<v8::Object> buffer = args[0]->ToObject(isolate);
    
    if (!node::Buffer::HasInstance(buffer)) {
        isolate->ThrowException(v8::Exception::TypeError(
            v8::String::NewFromUtf8(isolate, "Argument should be a buffer object.")));
        return;
    }
    
    char* input = node::Buffer::Data(buffer);
    size_t input_len = node::Buffer::Length(buffer);
    
    char output[32];
    
    xelishash_hash(input, output, input_len);
    
    v8::Local<v8::Value> returnValue = node::Buffer::Copy(
        isolate, 
        output,
        32).ToLocalChecked();
        
    args.GetReturnValue().Set(returnValue);
}

void method_v2(const v8::FunctionCallbackInfo<v8::Value>& args) {
    v8::Isolate* isolate = args.GetIsolate();
    
    if (args.Length() < 1) {
        isolate->ThrowException(v8::Exception::TypeError(
            v8::String::NewFromUtf8(isolate, "Wrong number of arguments")));
        return;
    }
    
    v8::Local<v8::Object> buffer = args[0]->ToObject(isolate);
    
    if (!node::Buffer::HasInstance(buffer)) {
        isolate->ThrowException(v8::Exception::TypeError(
            v8::String::NewFromUtf8(isolate, "Argument should be a buffer object.")));
        return;
    }
    
    char* input = node::Buffer::Data(buffer);
    size_t input_len = node::Buffer::Length(buffer);
    
    char output[32];
    
    xelishash_v2(input, output, input_len);
    
    v8::Local<v8::Value> returnValue = node::Buffer::Copy(
        isolate, 
        output,
        32).ToLocalChecked();
        
    args.GetReturnValue().Set(returnValue);
}

NODE_MODULE(xelishash, init)