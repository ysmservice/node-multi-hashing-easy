#include <node.h>
#include <node_buffer.h>
#include <v8.h>
#include <stdint.h>
#include "nan.h"

#include <equihash/equihash.h>

using v8::FunctionCallbackInfo;
using v8::Isolate;
using v8::Local;
using v8::Object;
using v8::Value;

void Equihash(const FunctionCallbackInfo<Value>& args) {
    Isolate* isolate = args.GetIsolate();

    if (args.Length() < 2) {
        isolate->ThrowException(v8::Exception::TypeError(
            v8::String::NewFromUtf8(isolate, "Wrong number of arguments")));
        return;
    }

    Local<Object> header = args[0]->ToObject(isolate);
    Local<Object> params = args[1]->ToObject(isolate);

    if (!node::Buffer::HasInstance(header)) {
        isolate->ThrowException(v8::Exception::TypeError(
            v8::String::NewFromUtf8(isolate, "Argument 1 should be a buffer")));
        return;
    }

    unsigned int n = params->Get(v8::String::NewFromUtf8(isolate, "N"))->Uint32Value();
    unsigned int k = params->Get(v8::String::NewFromUtf8(isolate, "K"))->Uint32Value();
    v8::String::Utf8Value personalization(params->Get(v8::String::NewFromUtf8(isolate, "personalization")));

    char* input = node::Buffer::Data(header);
    size_t input_len = node::Buffer::Length(header);

    // ZCashのEquihashライブラリを使用して解を検証
    bool is_valid = equihash::Verify(
        input,
        input_len,
        n,
        k,
        *personalization
    );

    args.GetReturnValue().Set(is_valid);
}

void Init(v8::Local<v8::Object> exports) {
    NODE_SET_METHOD(exports, "equihash", Equihash);
}

NODE_MODULE(equihash, Init)