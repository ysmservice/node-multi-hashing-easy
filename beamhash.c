#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "sha256.h"

// BeamHash IIIパラメータ
#define BEAM_N 144
#define BEAM_K 5
#define BEAM_NONCE_SIZE 32

void beamhash_hash(const char* input, char* output, uint32_t len) {
    uint32_t hash[8];
    
    // First pass - SHA256
    sha256_ctx ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, input, len);
    sha256_final(&ctx, (unsigned char*)hash);
    
    // BeamHash III処理
    uint32_t beam_state[BEAM_N];
    memcpy(beam_state, hash, 32);
    
    // BeamHash IIIメインループ
    for(int i = 0; i < BEAM_K; i++) {
        // FNV-1aハッシュ関数
        const uint32_t FNV_PRIME = 0x01000193;
        const uint32_t FNV_OFFSET = 0x811C9DC5;
        
        uint32_t fnv = FNV_OFFSET;
        for(int j = 0; j < BEAM_N; j++) {
            fnv = (fnv ^ beam_state[j]) * FNV_PRIME;
        }
        
        // 状態の更新
        for(int j = 0; j < BEAM_N; j++) {
            beam_state[j] = beam_state[j] ^ fnv;
            beam_state[j] = ((beam_state[j] << 13) | (beam_state[j] >> 19));
        }
    }
    
    // 最終ハッシュの生成
    sha256_init(&ctx);
    sha256_update(&ctx, (const char*)beam_state, BEAM_N * 4);
    sha256_final(&ctx, (unsigned char*)output);
}

#include <node.h>
#include <node_buffer.h>
#include <v8.h>

void init(v8::Handle<v8::Object> exports) {
    NODE_SET_METHOD(exports, "beamhash", method);
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
    
    beamhash_hash(input, output, input_len);
    
    v8::Local<v8::Value> returnValue = node::Buffer::Copy(
        isolate, 
        output,
        32).ToLocalChecked();
        
    args.GetReturnValue().Set(returnValue);
}

NODE_MODULE(beamhash, init)