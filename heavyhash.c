#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "sha256.h"
#include "heavyhash.h"

void heavyhash_hash(const char* input, char* output, uint32_t len) {
    uint32_t hash[8];
    
    // First pass - SHA256
    sha256_ctx ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, input, len);
    sha256_final(&ctx, (unsigned char*)hash);
    
    // Second pass - Extra mixing function
    uint32_t p1[8];
    memcpy(p1, hash, 32);
    
    // Mix with constants
    const uint32_t k[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };
    
    for (int i = 0; i < 8; i++) {
        p1[i] ^= k[i];
    }
    
    // Third pass - Final SHA256
    sha256_init(&ctx);
    sha256_update(&ctx, (const char*)p1, 32);
    sha256_final(&ctx, (unsigned char*)output);
}

#include <node.h>
#include <node_buffer.h>
#include <v8.h>

void init(v8::Handle<v8::Object> exports) {
    NODE_SET_METHOD(exports, "heavyhash", method);
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
    
    heavyhash_hash(input, output, input_len);
    
    v8::Local<v8::Value> returnValue = node::Buffer::Copy(
        isolate, 
        output,
        32).ToLocalChecked();
        
    args.GetReturnValue().Set(returnValue);
}

NODE_MODULE(heavyhash, init)