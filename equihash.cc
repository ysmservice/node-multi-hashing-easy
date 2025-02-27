#include <node.h>
#include <node_buffer.h>
#include <v8.h>
#include <stdint.h>
#include "nan.h"

#include "crypto/equihash.h"

using v8::FunctionCallbackInfo;
using v8::Isolate;
using v8::Local;
using v8::Object;
using v8::Value;


int verifyEH(const char *hdr, const std::vector<unsigned char> &soln, unsigned int n = 200, unsigned int k = 9) {
    // Hash state
    crypto_generichash_blake2b_state state;
    EhInitialiseState(n, k, state);

    crypto_generichash_blake2b_update(&state, (const unsigned char*)hdr, 140);

    bool isValid;
    if (n == 96 && k == 3) {
        isValid = Eh96_3.IsValidSolution(state, soln);
    } else if (n == 200 && k == 9) {
        isValid = Eh200_9.IsValidSolution(state, soln);
    } else if (n == 144 && k == 5) {
        isValid = Eh144_5.IsValidSolution(state, soln);
    } else if (n == 192 && k == 7) {
        isValid = Eh192_7.IsValidSolution(state, soln);
    } else if (n == 96 && k == 5) {
        isValid = Eh96_5.IsValidSolution(state, soln);
    } else if (n == 48 && k == 5) {
        isValid = Eh48_5.IsValidSolution(state, soln);
    } else {
        throw std::invalid_argument("Unsupported Equihash parameters");
    }

    return isValid;
}

void Verify(const v8::FunctionCallbackInfo<Value>& args) {
    Isolate* isolate = Isolate::GetCurrent();
    HandleScope scope(isolate);

    unsigned int n = 200;
    unsigned int k = 9;

    if (args.Length() < 2) {
        isolate->ThrowException(Exception::TypeError(
            String::NewFromUtf8(isolate, "Wrong number of arguments")));
        return;
    }

    Local<Object> header = args[0]->ToObject();
    Local<Object> solution = args[1]->ToObject();

    if (args.Length() == 4) {
        n = args[2]->Uint32Value();
        k = args[3]->Uint32Value();
    }

    if(!node::Buffer::HasInstance(header) || !node::Buffer::HasInstance(solution)) {
        isolate->ThrowException(Exception::TypeError(
            String::NewFromUtf8(isolate, "Arguments should be buffer objects.")));
        return;
    }

    const char *hdr = node::Buffer::Data(header);
    if(node::Buffer::Length(header) != 140) {
        //invalid hdr length
        args.GetReturnValue().Set(false);
        return;
    }
    const char *soln = node::Buffer::Data(solution);

    std::vector<unsigned char> vecSolution(soln, soln + node::Buffer::Length(solution));

    bool result = verifyEH(hdr, vecSolution, n, k);
    args.GetReturnValue().Set(result);
}



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
    bool is_valid = Verify(
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