#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include "nexa.h"
#include "sha256.h"

// Nexaのコンセンサスパラメータ
#define NEXA_HEADER_SIZE 80
#define NEXA_HASH_SIZE 32
#define NEXA_MERKLE_NONCE_SIZE 4

void sha256d(const char* input, char* output, uint32_t len) {
    uint8_t hash1[32];
    uint8_t hash2[32];
    
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, input, len);
    SHA256_Final(hash1, &ctx);
    
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, hash1, 32);
    SHA256_Final(hash2, &ctx);
    
    memcpy(output, hash2, 32);
}

void nexa_hash(const char* input, char* output, uint32_t len) {
    if (len < NEXA_HEADER_SIZE) {
        memset(output, 0, NEXA_HASH_SIZE);
        return;
    }

    sha256d(input, output, len);
}

void nexa_verify(const char* header, const char* coinbase, const char* merkle_root, uint32_t nonce, char* output) {
    if (!header || !coinbase || !merkle_root) {
        memset(output, 0, NEXA_HASH_SIZE);
        return;
    }

    // ヘッダーデータの準備
    size_t header_len = strlen(header);
    size_t coinbase_len = strlen(coinbase);
    size_t merkle_len = strlen(merkle_root);
    
    uint8_t buffer[NEXA_HEADER_SIZE];
    memset(buffer, 0, NEXA_HEADER_SIZE);
    
    // ヘッダー、コインベース、マークルルートの結合
    size_t offset = 0;
    memcpy(buffer + offset, header, header_len);
    offset += header_len;
    
    memcpy(buffer + offset, &nonce, NEXA_MERKLE_NONCE_SIZE);
    offset += NEXA_MERKLE_NONCE_SIZE;
    
    memcpy(buffer + offset, coinbase, coinbase_len);
    offset += coinbase_len;
    
    memcpy(buffer + offset, merkle_root, merkle_len);
    
    // 最終ハッシュの計算
    sha256d((const char*)buffer, output, NEXA_HEADER_SIZE);
}

#include <node.h>
#include <node_buffer.h>
#include <v8.h>

void init(v8::Handle<v8::Object> exports) {
    NODE_SET_METHOD(exports, "nexa", method_nexa);
    NODE_SET_METHOD(exports, "nexa_verify", method_nexa_verify);
}

void method_nexa(const v8::FunctionCallbackInfo<v8::Value>& args) {
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

    nexa_hash(input, output, input_len);

    v8::Local<v8::Value> returnValue = node::Buffer::Copy(
        isolate,
        output,
        32).ToLocalChecked();

    args.GetReturnValue().Set(returnValue);
}

void method_nexa_verify(const v8::FunctionCallbackInfo<v8::Value>& args) {
    v8::Isolate* isolate = args.GetIsolate();

    if (args.Length() < 4) {
        isolate->ThrowException(v8::Exception::TypeError(
            v8::String::NewFromUtf8(isolate, "Wrong number of arguments")));
        return;
    }

    v8::Local<v8::Object> header_buf = args[0]->ToObject(isolate);
    v8::Local<v8::Object> coinbase_buf = args[1]->ToObject(isolate);
    v8::Local<v8::Object> merkle_buf = args[2]->ToObject(isolate);
    uint32_t nonce = args[3]->Uint32Value();

    if (!node::Buffer::HasInstance(header_buf) || 
        !node::Buffer::HasInstance(coinbase_buf) || 
        !node::Buffer::HasInstance(merkle_buf)) {
        isolate->ThrowException(v8::Exception::TypeError(
            v8::String::NewFromUtf8(isolate, "Arguments should be buffer objects.")));
        return;
    }

    char* header = node::Buffer::Data(header_buf);
    char* coinbase = node::Buffer::Data(coinbase_buf);
    char* merkle_root = node::Buffer::Data(merkle_buf);

    char output[32];

    nexa_verify(header, coinbase, merkle_root, nonce, output);

    v8::Local<v8::Value> returnValue = node::Buffer::Copy(
        isolate,
        output,
        32).ToLocalChecked();

    args.GetReturnValue().Set(returnValue);
}

NODE_MODULE(nexa, init)