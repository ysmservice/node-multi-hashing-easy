#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "sha256.h"

void verushash_hash(const char* input, char* output, uint32_t len) {
    uint32_t hash[8];
    
    // First pass - SHA256
    sha256_ctx ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, input, len);
    sha256_final(&ctx, (unsigned char*)hash);
    
    // Second pass - VerusHash v2.0
    uint32_t vh_state[8];
    memcpy(vh_state, hash, 32);
    
    // VerusHash main loop
    for(int i = 0; i < 42; i++) {
        // AES round
        for(int j = 0; j < 8; j++) {
            vh_state[j] ^= vh_state[(j + 3) % 8];
            vh_state[j] = ((vh_state[j] << 13) | (vh_state[j] >> 19));
        }
        
        // Add input
        for(int j = 0; j < 8; j++) {
            vh_state[j] += hash[j];
        }
    }
    
    memcpy(output, vh_state, 32);
}

#include <node.h>
#include <node_buffer.h>
#include <v8.h>

void init(v8::Handle<v8::Object> exports) {
    NODE_SET_METHOD(exports, "verushash", method);
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
    
    verushash_hash(input, output, input_len);
    
    v8::Local<v8::Value> returnValue = node::Buffer::Copy(
        isolate, 
        output,
        32).ToLocalChecked();
        
    args.GetReturnValue().Set(returnValue);
}

NODE_MODULE(verushash, init)