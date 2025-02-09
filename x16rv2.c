#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "sha3/sph_blake.h"
#include "sha3/sph_bmw.h"
#include "sha3/sph_groestl.h"
#include "sha3/sph_jh.h"
#include "sha3/sph_keccak.h"
#include "sha3/sph_skein.h"
#include "sha3/sph_luffa.h"
#include "sha3/sph_cubehash.h"
#include "sha3/sph_shavite.h"
#include "sha3/sph_simd.h"
#include "sha3/sph_echo.h"
#include "sha3/sph_hamsi.h"
#include "sha3/sph_fugue.h"
#include "sha3/sph_shabal.h"
#include "sha3/sph_whirlpool.h"
#include "sha3/sph_sha2.h"

#define HASH_FUNC_BASE_TIMESTAMP 1569008790
#define HASH_FUNC_COUNT 16
#define HASH_FUNC_COUNT_PERMUTATIONS 16

static const char* ALGORITHM_NAMES[] = {
    "blake", "bmw", "groestl", "jh", "keccak", "skein", "luffa", "cubehash",
    "shavite", "simd", "echo", "hamsi", "fugue", "shabal", "whirlpool", "sha512"
};

static void get_hash_order(const char* input, char* order) {
    for (int i = 0; i < HASH_FUNC_COUNT; i++) {
        uint8_t b = input[i];
        order[i] = b % HASH_FUNC_COUNT;
    }
}

void x16rv2_hash(const char* input, char* output, uint32_t len) {
    uint32_t hash[64/4];
    
    sph_blake512_context     ctx_blake;
    sph_bmw512_context      ctx_bmw;
    sph_groestl512_context  ctx_groestl;
    sph_jh512_context       ctx_jh;
    sph_keccak512_context   ctx_keccak;
    sph_skein512_context    ctx_skein;
    sph_luffa512_context    ctx_luffa;
    sph_cubehash512_context ctx_cubehash;
    sph_shavite512_context  ctx_shavite;
    sph_simd512_context     ctx_simd;
    sph_echo512_context     ctx_echo;
    sph_hamsi512_context    ctx_hamsi;
    sph_fugue512_context    ctx_fugue;
    sph_shabal512_context   ctx_shabal;
    sph_whirlpool_context   ctx_whirlpool;
    sph_sha512_context      ctx_sha512;
    
    void *in = (void*) input;
    int size = len;
    char order[HASH_FUNC_COUNT] = {0};
    get_hash_order(input, order);
    
    for (int i = 0; i < HASH_FUNC_COUNT; i++) {
        const uint8_t algo = order[i];
        
        switch (algo) {
            case 0:
                sph_blake512_init(&ctx_blake);
                sph_blake512(&ctx_blake, in, size);
                sph_blake512_close(&ctx_blake, hash);
                break;
            case 1:
                sph_bmw512_init(&ctx_bmw);
                sph_bmw512(&ctx_bmw, in, size);
                sph_bmw512_close(&ctx_bmw, hash);
                break;
            case 2:
                sph_groestl512_init(&ctx_groestl);
                sph_groestl512(&ctx_groestl, in, size);
                sph_groestl512_close(&ctx_groestl, hash);
                break;
            case 3:
                sph_jh512_init(&ctx_jh);
                sph_jh512(&ctx_jh, in, size);
                sph_jh512_close(&ctx_jh, hash);
                break;
            case 4:
                sph_keccak512_init(&ctx_keccak);
                sph_keccak512(&ctx_keccak, in, size);
                sph_keccak512_close(&ctx_keccak, hash);
                break;
            case 5:
                sph_skein512_init(&ctx_skein);
                sph_skein512(&ctx_skein, in, size);
                sph_skein512_close(&ctx_skein, hash);
                break;
            case 6:
                sph_luffa512_init(&ctx_luffa);
                sph_luffa512(&ctx_luffa, in, size);
                sph_luffa512_close(&ctx_luffa, hash);
                break;
            case 7:
                sph_cubehash512_init(&ctx_cubehash);
                sph_cubehash512(&ctx_cubehash, in, size);
                sph_cubehash512_close(&ctx_cubehash, hash);
                break;
            case 8:
                sph_shavite512_init(&ctx_shavite);
                sph_shavite512(&ctx_shavite, in, size);
                sph_shavite512_close(&ctx_shavite, hash);
                break;
            case 9:
                sph_simd512_init(&ctx_simd);
                sph_simd512(&ctx_simd, in, size);
                sph_simd512_close(&ctx_simd, hash);
                break;
            case 10:
                sph_echo512_init(&ctx_echo);
                sph_echo512(&ctx_echo, in, size);
                sph_echo512_close(&ctx_echo, hash);
                break;
            case 11:
                sph_hamsi512_init(&ctx_hamsi);
                sph_hamsi512(&ctx_hamsi, in, size);
                sph_hamsi512_close(&ctx_hamsi, hash);
                break;
            case 12:
                sph_fugue512_init(&ctx_fugue);
                sph_fugue512(&ctx_fugue, in, size);
                sph_fugue512_close(&ctx_fugue, hash);
                break;
            case 13:
                sph_shabal512_init(&ctx_shabal);
                sph_shabal512(&ctx_shabal, in, size);
                sph_shabal512_close(&ctx_shabal, hash);
                break;
            case 14:
                sph_whirlpool_init(&ctx_whirlpool);
                sph_whirlpool(&ctx_whirlpool, in, size);
                sph_whirlpool_close(&ctx_whirlpool, hash);
                break;
            case 15:
                sph_sha512_init(&ctx_sha512);
                sph_sha512(&ctx_sha512, in, size);
                sph_sha512_close(&ctx_sha512, hash);
                break;
        }
        
        in = (void*) hash;
        size = 64;
    }
    
    memcpy(output, hash, 32);
}

#include <node.h>
#include <node_buffer.h>
#include <v8.h>

void init(v8::Handle<v8::Object> exports) {
    NODE_SET_METHOD(exports, "x16rv2", method);
}

void method(const v8::FunctionCallbackInfo<v8::Value>& args) {
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
    
    x16rv2_hash(input, output, input_len);
    
    v8::Local<v8::Value> returnValue = node::Buffer::Copy(
        isolate, 
        output,
        32).ToLocalChecked();
        
    args.GetReturnValue().Set(returnValue);
}

NODE_MODULE(x16rv2, init)