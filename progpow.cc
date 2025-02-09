#include <node.h>
#include <node_buffer.h>
#include <v8.h>
#include <stdint.h>
#include "progpow.h"

using namespace node;
using namespace v8;

void init_progpow_context(Local<Object> exports) {
    NODE_SET_METHOD(exports, "progpow_hash", progpow_hash_wrapper);
}

void progpow_hash_wrapper(const FunctionCallbackInfo<Value>& args) {
    Isolate* isolate = Isolate::GetCurrent();
    HandleScope scope(isolate);

    if (args.Length() < 1) {
        isolate->ThrowException(Exception::TypeError(
            String::NewFromUtf8(isolate, "Wrong number of arguments")));
        return;
    }

    Local<Object> buffer = args[0]->ToObject(isolate);
    if(!Buffer::HasInstance(buffer)) {
        isolate->ThrowException(Exception::TypeError(
            String::NewFromUtf8(isolate, "Argument should be a buffer object.")));
        return;
    }

    char * input = Buffer::Data(buffer);
    char output[32];

    progpow_params params = {
        .epoch_length = 7500,
        .dag_size = 0,
        .cache_size = 0
    };

    progpow_hash(input, output, Buffer::Length(buffer), &params);

    Local<Object> returnValue = Buffer::New(isolate, output, 32)->ToObject();
    args.GetReturnValue().Set(returnValue);
}

NODE_MODULE(progpow, init_progpow_context)