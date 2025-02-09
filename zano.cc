#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include "zano.h"
#include "crypto/cryptonight.h"
#include "crypto/c_keccak.h"

// Zanoのコンセンサスパラメータ
#define ZANO_BLOCK_HEADER_SIZE 76
#define ZANO_HASH_KEY_SIZE 32

void zano_hash(const char* input, char* output, uint32_t len) {
    if (len < ZANO_BLOCK_HEADER_SIZE) {
        memset(output, 0, 32);
        return;
    }

    // Keccakで初期ハッシュを計算
    uint8_t hash[200];
    keccak_hash(input, len, hash, 32);

    // CryptoNightでPOWハッシュを計算
    cryptonight_hash(hash, output, 32, 1);
}

void zano_pow(const char* input, char* output, uint32_t len, const char* seed_hash) {
    if (len < ZANO_BLOCK_HEADER_SIZE || !seed_hash) {
        memset(output, 0, 32);
        return;
    }

    // 入力データの準備
    uint8_t pow_hash[32];
    uint8_t seed[32];
    memcpy(seed, seed_hash, 32);

    // 初期ハッシュの計算
    zano_hash(input, (char*)pow_hash, len);

    // シードハッシュと組み合わせて最終ハッシュを生成
    uint8_t final_hash[64];
    memcpy(final_hash, pow_hash, 32);
    memcpy(final_hash + 32, seed, 32);

    // 最終的なPOWハッシュの計算
    keccak_hash(final_hash, 64, output, 32);
}

#include <node.h>
#include <node_buffer.h>
#include <v8.h>

void init(v8::Handle<v8::Object> exports) {
    NODE_SET_METHOD(exports, "zano", method_zano);
    NODE_SET_METHOD(exports, "zano_pow", method_zano_pow);
}

void method_zano(const v8::FunctionCallbackInfo<v8::Value>& args) {
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

    zano_hash(input, output, input_len);

    v8::Local<v8::Value> returnValue = node::Buffer::Copy(
        isolate,
        output,
        32).ToLocalChecked();

    args.GetReturnValue().Set(returnValue);
}

void method_zano_pow(const v8::FunctionCallbackInfo<v8::Value>& args) {
    v8::Isolate* isolate = args.GetIsolate();

    if (args.Length() < 2) {
        isolate->ThrowException(v8::Exception::TypeError(
            v8::String::NewFromUtf8(isolate, "Wrong number of arguments")));
        return;
    }

    v8::Local<v8::Object> buffer = args[0]->ToObject(isolate);
    v8::Local<v8::Object> seed_buffer = args[1]->ToObject(isolate);

    if (!node::Buffer::HasInstance(buffer) || !node::Buffer::HasInstance(seed_buffer)) {
        isolate->ThrowException(v8::Exception::TypeError(
            v8::String::NewFromUtf8(isolate, "Arguments should be buffer objects.")));
        return;
    }

    char* input = node::Buffer::Data(buffer);
    size_t input_len = node::Buffer::Length(buffer);
    char* seed_hash = node::Buffer::Data(seed_buffer);

    char output[32];

    zano_pow(input, output, input_len, seed_hash);

    v8::Local<v8::Value> returnValue = node::Buffer::Copy(
        isolate,
        output,
        32).ToLocalChecked();

    args.GetReturnValue().Set(returnValue);
}

NODE_MODULE(zano, init)