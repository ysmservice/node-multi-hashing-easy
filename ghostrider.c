#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "sha256.h"
#include "x11.h"
#include "x13.h"
#include "x15.h"

void ghostrider_hash(const char* input, char* output, uint32_t len) {
    uint32_t hash[8];
    
    // GhostRider使用するハッシュアルゴリズムの順序
    const int ALGO_COUNT = 5;
    const int ALGO_SEQUENCE[] = {
        0, // X16R
        1, // X16Rv2
        2, // X16Rt
        3, // X16Rt-new
        4  // X16Rt-b2
    };
    
    // 初期ハッシュ - SHA256
    sha256_ctx ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, input, len);
    sha256_final(&ctx, (unsigned char*)hash);
    
    // GhostRiderメインループ
    uint32_t current_hash[8];
    memcpy(current_hash, hash, 32);
    
    for(int i = 0; i < ALGO_COUNT; i++) {
        switch(ALGO_SEQUENCE[i]) {
            case 0: // X16R
                x11_hash(current_hash, output, 32);
                break;
            case 1: // X16Rv2
                x13_hash(current_hash, output, 32);
                break;
            case 2: // X16Rt
                x15_hash(current_hash, output, 32);
                break;
            case 3: // X16Rt-new
                x11_hash(current_hash, output, 32);
                break;
            case 4: // X16Rt-b2
                x13_hash(current_hash, output, 32);
                break;
        }
        memcpy(current_hash, output, 32);
    }
    
    memcpy(output, current_hash, 32);
}

#include <node.h>
#include <node_buffer.h>
#include <v8.h>

void init(v8::Handle<v8::Object> exports) {
    NODE_SET_METHOD(exports, "ghostrider", method);
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
    
    ghostrider_hash(input, output, input_len);
    
    v8::Local<v8::Value> returnValue = node::Buffer::Copy(
        isolate, 
        output,
        32).ToLocalChecked();
        
    args.GetReturnValue().Set(returnValue);
}

NODE_MODULE(ghostrider, init)