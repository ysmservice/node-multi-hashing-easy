#include <node.h>
#include <node_buffer.h>
#include <v8.h>
#include <stdint.h>
#include "meowpow.h"

using namespace node;
using namespace v8;

#include "meow/ethash/ethash.h"
#include "meow/ethash/ethash.hpp"
#include "meow/ethash/progpow.hpp"

void meowpow_hash(const char* input, char* output, uint32_t height, int *retval) {
    using namespace ethash;

    // Convert input to hash256
    hash256 header_hash;
    memcpy(&header_hash, input, sizeof(header_hash));

    // Get epoch number from block height
    int epoch_number = static_cast<int>(height / ethash::epoch_length);
    
    // Initialize context
    ethash::epoch_context_full context = ethash::create_epoch_context_full(epoch_number);
    
    // Calculate hash
    result res = progpow::hash(*context, height, header_hash, 0);
    
    // Copy result to output
    memcpy(output, &res.final_hash, sizeof(res.final_hash));
    
    if (retval) *retval = 0;
}

void init(Local<Object> exports) {
    NODE_SET_METHOD(exports, "meowpow", [](const FunctionCallbackInfo<Value>& args) {
        Isolate* isolate = Isolate::GetCurrent();
        HandleScope scope(isolate);

        if (args.Length() < 3) {
            isolate->ThrowException(Exception::TypeError(
                String::NewFromUtf8(isolate, "Wrong number of arguments")));
            return;
        }

        Local<Object> header = args[0]->ToObject(isolate->GetCurrentContext()).ToLocalChecked();
        Local<Object> target = args[1]->ToObject(isolate->GetCurrentContext()).ToLocalChecked();
        uint32_t height = args[2]->Uint32Value(isolate->GetCurrentContext()).ToChecked();

        if (!Buffer::HasInstance(header) || !Buffer::HasInstance(target)) {
            isolate->ThrowException(Exception::TypeError(
                String::NewFromUtf8(isolate, "Arguments should be buffer objects.")));
            return;
        }

        const char* input = Buffer::Data(header);
        char* output = Buffer::Data(target);

        int retval;
        meowpow_hash(input, output, height, &retval);

        args.GetReturnValue().Set(retval);
    });
}

NODE_MODULE(meowpow, init)