#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "sha256.h"

// Verthashのデータファイルのパス
#define VERTHASH_DATA_FILE "verthash.dat"
#define VERTHASH_DATASET_SIZE (1024*1024*32) // 32MB

static uint8_t* verthash_data = NULL;

void verthash_init() {
    if (verthash_data != NULL)
        return;
        
    FILE* fp = fopen(VERTHASH_DATA_FILE, "rb");
    if (fp == NULL) {
        fprintf(stderr, "Failed to open verthash.dat\n");
        return;
    }
    
    verthash_data = (uint8_t*)malloc(VERTHASH_DATASET_SIZE);
    if (verthash_data == NULL) {
        fclose(fp);
        fprintf(stderr, "Failed to allocate memory for verthash data\n");
        return;
    }
    
    size_t read = fread(verthash_data, 1, VERTHASH_DATASET_SIZE, fp);
    fclose(fp);
    
    if (read != VERTHASH_DATASET_SIZE) {
        free(verthash_data);
        verthash_data = NULL;
        fprintf(stderr, "Invalid verthash.dat size\n");
        return;
    }
}

void verthash_hash(const char* input, char* output, uint32_t len) {
    if (verthash_data == NULL) {
        verthash_init();
        if (verthash_data == NULL) {
            memset(output, 0, 32);
            return;
        }
    }
    
    uint32_t hash[8];
    
    // First pass - SHA256
    sha256_ctx ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, input, len);
    sha256_final(&ctx, (unsigned char*)hash);
    
    // Second pass - Verthash memory-hard function
    uint32_t p1[8];
    memcpy(p1, hash, 32);
    
    for(int i = 0; i < 1024; i++) {
        uint32_t idx = p1[0] % (VERTHASH_DATASET_SIZE - 32);
        for(int j = 0; j < 8; j++) {
            p1[j] ^= *(uint32_t*)(verthash_data + idx + (j * 4));
        }
        
        sha256_init(&ctx);
        sha256_update(&ctx, (const char*)p1, 32);
        sha256_final(&ctx, (unsigned char*)p1);
    }
    
    memcpy(output, p1, 32);
}

#include <node.h>
#include <node_buffer.h>
#include <v8.h>

void init(v8::Handle<v8::Object> exports) {
    NODE_SET_METHOD(exports, "verthash", method);
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
    
    verthash_hash(input, output, input_len);
    
    v8::Local<v8::Value> returnValue = node::Buffer::Copy(
        isolate, 
        output,
        32).ToLocalChecked();
        
    args.GetReturnValue().Set(returnValue);
}

NODE_MODULE(verthash, init)