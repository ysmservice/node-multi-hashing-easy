#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include "handshake.h"
#include "blake2b/blake2b.h"
#include "sha3/sha3.h"

// Handshakeのコンセンサスルール
#define HNS_WORK_FACTOR 9
#define HNS_HEADER_SIZE 228

void handshake_hash(const char* input, char* output, uint32_t len) {
    if (len != HNS_HEADER_SIZE) {
        memset(output, 0, 32);
        return;
    }

    // Blake2b-256の初期化
    blake2b_state S;
    blake2b_init(&S, 32);

    // ヘッダーのハッシュ
    blake2b_update(&S, input, len);
    
    uint8_t hash[32];
    blake2b_final(&S, hash, 32);

    // SHA3-256でさらにハッシュ
    sha3_context ctx;
    sha3_init(&ctx, 32);
    sha3_update(&ctx, hash, 32);
    sha3_final(hash, &ctx);

    // 難易度の調整
    uint8_t final_hash[32];
    for (int i = 0; i < 32; i++) {
        final_hash[i] = hash[i] >> HNS_WORK_FACTOR;
    }

    memcpy(output, final_hash, 32);
}

#include <node.h>
#include <node_buffer.h>
#include <v8.h>

void init(v8::Handle<v8::Object> exports) {
    NODE_SET_METHOD(exports, "handshake", method_handshake);
}

void method_handshake(const v8::FunctionCallbackInfo<v8::Value>& args) {
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

    handshake_hash(input, output, input_len);

    v8::Local<v8::Value> returnValue = node::Buffer::Copy(
        isolate,
        output,
        32).ToLocalChecked();

    args.GetReturnValue().Set(returnValue);
}

NODE_MODULE(handshake, init)