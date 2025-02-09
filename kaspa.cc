#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include "kaspa.h"
#include "blake2b/blake2b.h"

// Kaspaのコンセンサスパラメータ
#define KASPA_BLOCK_HEADER_SIZE 184
#define KASPA_TARGET_BITS 255
#define KASPA_DIFFICULTY_WINDOW 960

// PoWハッシュ計算用の定数
#define KASPA_POW_MAX_NONCE 0xFFFFFFFF
#define KASPA_POW_TARGET_SPACING 1
#define KASPA_POW_NO_RETARGETING false

void kaspa_hash(const char* input, char* output, uint32_t len) {
    // Blake2bの初期化
    blake2b_state S;
    blake2b_init(&S, 32);

    // 入力データのハッシュ化
    blake2b_update(&S, input, len);
    
    uint8_t hash[32];
    blake2b_final(&S, hash, 32);

    memcpy(output, hash, 32);
}

void kaspa_pow(const char* input, char* output, uint32_t len) {
    if (len != KASPA_BLOCK_HEADER_SIZE) {
        memset(output, 0, 32);
        return;
    }

    // ブロックヘッダーから必要なフィールドを抽出
    uint32_t version;
    uint8_t previous_hash[32];
    uint8_t merkle_root[32];
    uint64_t timestamp;
    uint32_t bits;
    uint32_t nonce;

    memcpy(&version, input, 4);
    memcpy(previous_hash, input + 4, 32);
    memcpy(merkle_root, input + 36, 32);
    memcpy(&timestamp, input + 68, 8);
    memcpy(&bits, input + 76, 4);
    memcpy(&nonce, input + 80, 4);

    // ハッシュ計算用のバッファ
    uint8_t hash_buffer[KASPA_BLOCK_HEADER_SIZE];
    memcpy(hash_buffer, input, KASPA_BLOCK_HEADER_SIZE);

    // Blake2bの初期化
    blake2b_state S;
    blake2b_init(&S, 32);

    // PoWハッシュの計算
    blake2b_update(&S, hash_buffer, KASPA_BLOCK_HEADER_SIZE);
    
    uint8_t hash[32];
    blake2b_final(&S, hash, 32);

    memcpy(output, hash, 32);
}

#include <node.h>
#include <node_buffer.h>
#include <v8.h>

void init(v8::Handle<v8::Object> exports) {
    NODE_SET_METHOD(exports, "kaspa", method_kaspa);
    NODE_SET_METHOD(exports, "kaspa_pow", method_kaspa_pow);
}

void method_kaspa(const v8::FunctionCallbackInfo<v8::Value>& args) {
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

    kaspa_hash(input, output, input_len);

    v8::Local<v8::Value> returnValue = node::Buffer::Copy(
        isolate,
        output,
        32).ToLocalChecked();

    args.GetReturnValue().Set(returnValue);
}

void method_kaspa_pow(const v8::FunctionCallbackInfo<v8::Value>& args) {
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

    kaspa_pow(input, output, input_len);

    v8::Local<v8::Value> returnValue = node::Buffer::Copy(
        isolate,
        output,
        32).ToLocalChecked();

    args.GetReturnValue().Set(returnValue);
}

NODE_MODULE(kaspa, init)