#include <node.h>
#include <node_buffer.h>
#include <v8.h>
#include <stdint.h>
#include <cstring>
#include <x86intrin.h>

extern "C" {
    #include "argon2.h"
    #include "bcrypt.h"
    #include "blake.h"
    #include "c11.h"
    #include "cryptonight.h"
    #include "cryptonight_dark.h"
    #include "cryptonight_dark_lite.h"
    #include "cryptonight_fast.h"
    #include "cryptonight_lite.h"
    #include "cryptonight_turtle.h"
    #include "cryptonight_turtle_lite.h"
    #include "cryptonight_soft_shell.h"
    #include "fresh.h"
    #include "fugue.h"
    #include "groestl.h"
    #include "hefty1.h"
    #include "keccak.h"
    #include "nist5.h"
    #include "quark.h"
    #include "qubit.h"
    #include "scryptjane.h"
    #include "scryptn.h"
    #include "sha1.h"
    #include "shavite3.h"
    #include "skein.h"
    #include "x11.h"
    #include "x13.h"
    #include "x15.h"
    #include "equihash.h"
    #include "yescrypt.h"
    #include "yescryptR8.h"
    #include "yescryptR16.h"
    #include "yescryptR32.h"
    #include "progpow.h"
    #include "xelishash.h"
    #include "yespowerr16.h"
    #include "meowpow.h"
    #include "ethash.h"
    #include "nexa.h"
}

#include "boolberry.h"

using namespace node;
using namespace v8;


#if NODE_MAJOR_VERSION >= 4
// ...既存のコードは変更なし...

#define DECLARE_INIT(x) \
    void x(Local<Object> exports)
#define DECLARE_FUNC(x) \
    void x(const FunctionCallbackInfo<Value>& args)
#define DECLARE_SCOPE \
    v8::Isolate* isolate = args.GetIsolate();
#define SET_BUFFER_RETURN(x, len) \
    args.GetReturnValue().Set(Buffer::Copy(isolate, x, len).ToLocalChecked());
#define SET_BOOLEAN_RETURN(x) \
    args.GetReturnValue().Set(Boolean::New(isolate, x));
#define RETURN_EXCEPT(msg) \
    do { \
        isolate->ThrowException(Exception::Error(String::NewFromUtf8(isolate, msg))); \
        return; \
    } while (0)
#else
#define DECLARE_INIT(x) \
    void x(Handle<Object> exports)
#define DECLARE_FUNC(x) \
    Handle<Value> x(const Arguments& args)
#define DECLARE_SCOPE \
    HandleScope scope
#define SET_BUFFER_RETURN(x, len) \
    do { \
        Buffer* buff = Buffer::New(x, len); \
        return scope.Close(buff->handle_); \
    } while (0)
#define SET_BOOLEAN_RETURN(x) \
    return scope.Close(Boolean::New(x));
#define RETURN_EXCEPT(msg) \
    return ThrowException(Exception::Error(String::New(msg)))
#endif // NODE_MAJOR_VERSION
#define DECLARE_CALLBACK_WITH_EPOCH(name, hash, output_len) \
    DECLARE_FUNC(name) { \
        DECLARE_SCOPE; \
\
        if (args.Length() < 1) \
            RETURN_EXCEPT("You must provide one argument."); \
\
        Local<Object> target = args[0]->ToObject(); \
\
        if(!Buffer::HasInstance(target)) \
            RETURN_EXCEPT("Argument should be a buffer object."); \
\
        char * input = Buffer::Data(target); \
        char output[32]; \
\
        uint32_t input_len = Buffer::Length(target); \
        int* epoch_number = new int(0); \
\
        if (args.Length() > 1 && args[1]->IsNumber()) { \
            *epoch_number = args[1]->Uint32Value(); \
        } \
\
        hash(input, output, input_len, epoch_number); \
\
        SET_BUFFER_RETURN(output, output_len); \
    }

#define DECLARE_CALLBACK(name, hash, output_len) \
    DECLARE_FUNC(name) { \
        DECLARE_SCOPE; \
\
        if (args.Length() < 1) \
            RETURN_EXCEPT("You must provide one argument."); \
\
        Local<Object> target = args[0]->ToObject(); \
\
        if(!Buffer::HasInstance(target)) \
            RETURN_EXCEPT("Argument should be a buffer object."); \
\
        char * input = Buffer::Data(target); \
        char output[32]; \
\
        uint32_t input_len = Buffer::Length(target); \
\
        hash(input, output, input_len); \
\
        SET_BUFFER_RETURN(output, output_len); \
    }
 DECLARE_CALLBACK(bcrypt, bcrypt_hash, 32);
 DECLARE_CALLBACK(blake, blake_hash, 32);
 DECLARE_CALLBACK(c11, c11_hash, 32);
 DECLARE_CALLBACK(fresh, fresh_hash, 32);
 DECLARE_CALLBACK(fugue, fugue_hash, 32);
 DECLARE_CALLBACK(groestl, groestl_hash, 32);
 DECLARE_CALLBACK(groestlmyriad, groestlmyriad_hash, 32);
 DECLARE_CALLBACK(hefty1, hefty1_hash, 32);
 DECLARE_CALLBACK(keccak, keccak_hash, 32);
 DECLARE_CALLBACK(nist5, nist5_hash, 32);
 DECLARE_CALLBACK(quark, quark_hash, 32);
 DECLARE_CALLBACK(qubit, qubit_hash, 32);
 DECLARE_CALLBACK(sha1, sha1_hash, 32);
 DECLARE_CALLBACK(shavite3, shavite3_hash, 32);
 DECLARE_CALLBACK(skein, skein_hash, 32);
 DECLARE_CALLBACK(x11, x11_hash, 32);
 DECLARE_CALLBACK(x13, x13_hash, 32);
 DECLARE_CALLBACK(x15, x15_hash, 32);
DECLARE_CALLBACK(xelishash, xelishash_hash, 32);
DECLARE_CALLBACK(xelishash_v2_wrapper, xelishash_v2, 32);
DECLARE_CALLBACK(yescryptR8, yescryptR8_hash, 32);
DECLARE_CALLBACK(yescryptR16, yescryptR16_hash, 32);
DECLARE_CALLBACK(yescryptR32, yescryptR32_hash, 32);
DECLARE_CALLBACK(ethash, ethash_hash, 32);
DECLARE_CALLBACK(yescrypt_wrapper, yescryptR8_hash, 32);
DECLARE_CALLBACK(yespowerr16_wrapper, yespowerR16_hash, 32);
DECLARE_CALLBACK(xelishash_wrapper, xelishash_hash, 32);
DECLARE_CALLBACK_WITH_EPOCH(meowpow, meowpow_hash, 32);
DECLARE_CALLBACK(nexa_wrapper, nexa_hash, 32);
DECLARE_FUNC(equihash_wrapper) {
    DECLARE_SCOPE;

    if (args.Length() < 1)
        RETURN_EXCEPT("You must provide one argument.");

    Local<Object> target = args[0]->ToObject();

    if(!Buffer::HasInstance(target))
        RETURN_EXCEPT("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char output[32];
    uint32_t input_len = Buffer::Length(target);

    // デフォルトのEquihashパラメータを設定
    EquihashParams params;
    params.N = args.Length() > 1 ? args[1]->Int32Value() : 200;
    params.K = args.Length() > 2 ? args[2]->Int32Value() : 9;
    
    // personalizationパラメータの処理
    const char* default_pers = "ZcashPoW";
    if (args.Length() > 3 && args[3]->IsString()) {
        v8::String::Utf8Value pers(args[3]);
        params.personalization = *pers;
    } else {
        params.personalization = default_pers;
    }

    equihash_hash(input, output, input_len, &params);

    SET_BUFFER_RETURN(output, 32);
}
DECLARE_FUNC(scrypt) {
   DECLARE_SCOPE;
   if (args.Length() < 3)
       RETURN_EXCEPT("You must provide buffer to hash, N value, and R value");
   Local<Object> target = args[0]->ToObject();
   if(!Buffer::HasInstance(target))
       RETURN_EXCEPT("Argument should be a buffer object.");
   unsigned int nValue = args[1]->Uint32Value();
   unsigned int rValue = args[2]->Uint32Value();
   char * input = Buffer::Data(target);
   char output[32];
   uint32_t input_len = Buffer::Length(target);
   scrypt_N_R_1_256(input, output, nValue, rValue, input_len);
   SET_BUFFER_RETURN(output, 32);
}
DECLARE_FUNC(scryptn) {
   DECLARE_SCOPE;
   if (args.Length() < 2)
       RETURN_EXCEPT("You must provide buffer to hash and N factor.");
   Local<Object> target = args[0]->ToObject();
   if(!Buffer::HasInstance(target))
       RETURN_EXCEPT("Argument should be a buffer object.");
   unsigned int nFactor = args[1]->Uint32Value();
   char * input = Buffer::Data(target);
   char output[32];
   uint32_t input_len = Buffer::Length(target);
   //unsigned int N = 1 << (getNfactor(input) + 1);
   unsigned int N = 1 << nFactor;
   scrypt_N_R_1_256(input, output, N, 1, input_len); //hardcode for now to R=1 for now
   SET_BUFFER_RETURN(output, 32);
}
DECLARE_FUNC(scryptjane) {
    DECLARE_SCOPE;
    if (args.Length() < 5)
        RETURN_EXCEPT("You must provide two argument: buffer, timestamp as number, and nChainStarTime as number, nMin, and nMax");
    Local<Object> target = args[0]->ToObject();
    if(!Buffer::HasInstance(target))
        RETURN_EXCEPT("First should be a buffer object.");
    int timestamp = args[1]->Int32Value();
    int nChainStartTime = args[2]->Int32Value();
    int nMin = args[3]->Int32Value();
    int nMax = args[4]->Int32Value();
    char * input = Buffer::Data(target);
    char output[32];
    uint32_t input_len = Buffer::Length(target);
    scryptjane_hash(input, input_len, (uint32_t *)output, GetNfactorJane(timestamp, nChainStartTime, nMin, nMax));
    SET_BUFFER_RETURN(output, 32);
}
DECLARE_FUNC(cryptonight) {
    DECLARE_SCOPE;
    bool fast = false;
    uint32_t cn_variant = 0;
    if (args.Length() < 1)
        RETURN_EXCEPT("You must provide one argument.");
    if (args.Length() >= 2) {
        if(args[1]->IsBoolean())
            fast = args[1]->BooleanValue();
        else if(args[1]->IsUint32())
            cn_variant = args[1]->Uint32Value();
        else
            RETURN_EXCEPT("Argument 2 should be a boolean or uint32_t");
    }
    Local<Object> target = args[0]->ToObject();
    if(!Buffer::HasInstance(target))
        RETURN_EXCEPT("Argument should be a buffer object.");
    char * input = Buffer::Data(target);
    char output[32];
    uint32_t input_len = Buffer::Length(target);
    if(fast)
        cryptonight_fast_hash(input, output, input_len);
    else {
        if (cn_variant > 0 && input_len < 43)
            RETURN_EXCEPT("Argument must be 43 bytes for monero variant 1+");
        cryptonight_hash(input, output, input_len, cn_variant);
    }
    SET_BUFFER_RETURN(output, 32);
}
DECLARE_FUNC(cryptonightdark) {
    DECLARE_SCOPE;
    bool fast = false;
    uint32_t cn_variant = 0;
    if (args.Length() < 1)
        RETURN_EXCEPT("You must provide one argument.");
    if (args.Length() >= 2) {
        if(args[1]->IsBoolean())
            fast = args[1]->BooleanValue();
        else if(args[1]->IsUint32())
            cn_variant = args[1]->Uint32Value();
        else
            RETURN_EXCEPT("Argument 2 should be a boolean or uint32_t");
    }
    Local<Object> target = args[0]->ToObject();
    if(!Buffer::HasInstance(target))
        RETURN_EXCEPT("Argument should be a buffer object.");
    char * input = Buffer::Data(target);
    char output[32];
    uint32_t input_len = Buffer::Length(target);
    if(fast)
        cryptonightdark_fast_hash(input, output, input_len);
    else {
        if (cn_variant > 0 && input_len < 43)
            RETURN_EXCEPT("Argument must be 43 bytes for monero variant 1+");
        cryptonightdark_hash(input, output, input_len, cn_variant);
    }
    SET_BUFFER_RETURN(output, 32);
}
DECLARE_FUNC(cryptonightdarklite) {
    DECLARE_SCOPE;
    bool fast = false;
    uint32_t cn_variant = 0;
    if (args.Length() < 1)
        RETURN_EXCEPT("You must provide one argument.");
    if (args.Length() >= 2) {
        if(args[1]->IsBoolean())
            fast = args[1]->BooleanValue();
        else if(args[1]->IsUint32())
            cn_variant = args[1]->Uint32Value();
        else
            RETURN_EXCEPT("Argument 2 should be a boolean or uint32_t");
    }
    Local<Object> target = args[0]->ToObject();
    if(!Buffer::HasInstance(target))
        RETURN_EXCEPT("Argument should be a buffer object.");
    char * input = Buffer::Data(target);
    char output[32];
    uint32_t input_len = Buffer::Length(target);
    if(fast)
        cryptonightdarklite_fast_hash(input, output, input_len);
    else {
        if (cn_variant > 0 && input_len < 43)
            RETURN_EXCEPT("Argument must be 43 bytes for monero variant 1+");
        cryptonightdarklite_hash(input, output, input_len, cn_variant);
    }
    SET_BUFFER_RETURN(output, 32);
}
DECLARE_FUNC(cryptonightlite) {
    DECLARE_SCOPE;
    bool fast = false;
    uint32_t cn_variant = 0;
    if (args.Length() < 1)
        RETURN_EXCEPT("You must provide one argument.");
    if (args.Length() >= 2) {
        if(args[1]->IsBoolean())
            fast = args[1]->BooleanValue();
        else if(args[1]->IsUint32())
            cn_variant = args[1]->Uint32Value();
        else
            RETURN_EXCEPT("Argument 2 should be a boolean or uint32_t");
    }
    Local<Object> target = args[0]->ToObject();
    if(!Buffer::HasInstance(target))
        RETURN_EXCEPT("Argument should be a buffer object.");
    char * input = Buffer::Data(target);
    char output[32];
    uint32_t input_len = Buffer::Length(target);
    if(fast)
        cryptonightlite_fast_hash(input, output, input_len);
    else {
        if (cn_variant > 0 && input_len < 43)
            RETURN_EXCEPT("Argument must be 43 bytes for monero variant 1+");
        cryptonightlite_hash(input, output, input_len, cn_variant);
    }
    SET_BUFFER_RETURN(output, 32);
}
DECLARE_FUNC(cryptonightturtle) {
    DECLARE_SCOPE;
    bool fast = false;
    uint32_t cn_variant = 0;
    if (args.Length() < 1)
        RETURN_EXCEPT("You must provide one argument.");
    if (args.Length() >= 2) {
        if(args[1]->IsBoolean())
            fast = args[1]->BooleanValue();
        else if(args[1]->IsUint32())
            cn_variant = args[1]->Uint32Value();
        else
            RETURN_EXCEPT("Argument 2 should be a boolean or uint32_t");
    }
    Local<Object> target = args[0]->ToObject();
    if(!Buffer::HasInstance(target))
        RETURN_EXCEPT("Argument should be a buffer object.");
    char * input = Buffer::Data(target);
    char output[32];
    uint32_t input_len = Buffer::Length(target);
    if(fast)
        cryptonightturtle_fast_hash(input, output, input_len);
    else {
        if (cn_variant > 0 && input_len < 43)
            RETURN_EXCEPT("Argument must be 43 bytes for monero variant 1+");
        cryptonightturtle_hash(input, output, input_len, cn_variant);
    }
    SET_BUFFER_RETURN(output, 32);
}
DECLARE_FUNC(cryptonightturtlelite) {
    DECLARE_SCOPE;
    bool fast = false;
    uint32_t cn_variant = 0;
    if (args.Length() < 1)
        RETURN_EXCEPT("You must provide one argument.");
    if (args.Length() >= 2) {
        if(args[1]->IsBoolean())
            fast = args[1]->BooleanValue();
        else if(args[1]->IsUint32())
            cn_variant = args[1]->Uint32Value();
        else
            RETURN_EXCEPT("Argument 2 should be a boolean or uint32_t");
    }
    Local<Object> target = args[0]->ToObject();
    if(!Buffer::HasInstance(target))
        RETURN_EXCEPT("Argument should be a buffer object.");
    char * input = Buffer::Data(target);
    char output[32];
    uint32_t input_len = Buffer::Length(target);
    if(fast)
        cryptonightturtlelite_fast_hash(input, output, input_len);
    else {
        if (cn_variant > 0 && input_len < 43)
            RETURN_EXCEPT("Argument must be 43 bytes for monero variant 1+");
        cryptonightturtlelite_hash(input, output, input_len, cn_variant);
    }
    SET_BUFFER_RETURN(output, 32);
}
DECLARE_FUNC(cryptonightfast) {
    DECLARE_SCOPE;
    bool fast = false;
    uint32_t cn_variant = 0;
    if (args.Length() < 1)
        RETURN_EXCEPT("You must provide one argument.");
    if (args.Length() >= 2) {
        if(args[1]->IsBoolean())
            fast = args[1]->BooleanValue();
        else if(args[1]->IsUint32())
            cn_variant = args[1]->Uint32Value();
        else
            RETURN_EXCEPT("Argument 2 should be a boolean or uint32_t");
    }
    Local<Object> target = args[0]->ToObject();
    if(!Buffer::HasInstance(target))
        RETURN_EXCEPT("Argument should be a buffer object.");
    char * input = Buffer::Data(target);
    char output[32];
    uint32_t input_len = Buffer::Length(target);
    if(fast)
        cryptonightfast_fast_hash(input, output, input_len);
    else {
        if (cn_variant > 0 && input_len < 43)
            RETURN_EXCEPT("Argument must be 43 bytes for monero variant 1+");
        cryptonightfast_hash(input, output, input_len, cn_variant);
    }
    SET_BUFFER_RETURN(output, 32);
}
DECLARE_FUNC(cryptonightsoftshell) {
    DECLARE_SCOPE;
    bool fast = false;
    uint32_t cn_variant = 0;
    uint32_t height = 0;
    if (args.Length() < 1)
      RETURN_EXCEPT("You must provide one argument.");
    if (args.Length() >= 2) {
        if(args[1]->IsBoolean())
            fast = args[1]->BooleanValue();
        else if(args[1]->IsUint32())
            cn_variant = args[1]->Uint32Value();
        else
            RETURN_EXCEPT("Argument 2 should be a boolean or uint32_t");
    }
    if (args.Length() >= 3) {
      if (args[2]->IsUint32())
        height = args[2]->Uint32Value();
      else
        RETURN_EXCEPT("Argument 3 should be an uint32_t");
    }
    /* Default CN Soft Shell values */
    uint32_t CN_SOFT_SHELL_MEMORY = 262144;
    uint32_t CN_SOFT_SHELL_ITER = (CN_SOFT_SHELL_MEMORY / 2);
    uint32_t CN_SOFT_SHELL_WINDOW = 2048;
    uint32_t CN_SOFT_SHELL_MULTIPLIER = 3;
    if (args.Length() >= 4) {
      if (args[3]->IsUint32()) {
        CN_SOFT_SHELL_MEMORY = args[3]->Uint32Value();
        CN_SOFT_SHELL_ITER  = (CN_SOFT_SHELL_MEMORY / 2);
      } else {
        RETURN_EXCEPT("Argument 4 should be an uint32_t (scratchpad)");
      }
    }
    if (args.Length() >= 5) {
      if (args[4]->IsUint32())
        CN_SOFT_SHELL_WINDOW = args[4]->Uint32Value();
      else
        RETURN_EXCEPT("Argument 6 should be an uint32_t (window)");
    }
    if (args.Length() >= 6) {
      if (args[5]->IsUint32())
        CN_SOFT_SHELL_MULTIPLIER = args[5]->Uint32Value();
      else
        RETURN_EXCEPT("Argument 6 should be an uint32_t (multiplier)");
    }
    uint32_t CN_SOFT_SHELL_PAD_MULTIPLIER = (CN_SOFT_SHELL_WINDOW / CN_SOFT_SHELL_MULTIPLIER);
    uint32_t CN_SOFT_SHELL_ITER_MULTIPLIER = (CN_SOFT_SHELL_PAD_MULTIPLIER / 2);
    Local<Object> target = args[0]->ToObject();
    uint32_t base_offset = (height % CN_SOFT_SHELL_WINDOW);
    int32_t offset = (height % (CN_SOFT_SHELL_WINDOW * 2)) - (base_offset * 2);
    if (offset < 0) {
      offset = base_offset;
    }
    uint32_t scratchpad = CN_SOFT_SHELL_MEMORY + (static_cast<uint32_t>(offset) * CN_SOFT_SHELL_PAD_MULTIPLIER);
	scratchpad = (static_cast<uint64_t>(scratchpad / 128)) * 128;
    uint32_t iterations = CN_SOFT_SHELL_ITER + (static_cast<uint32_t>(offset) * CN_SOFT_SHELL_ITER_MULTIPLIER);
    char * input = Buffer::Data(target);
    char output[32];
    uint32_t input_len = Buffer::Length(target);
    if(fast)
        cryptonight_soft_shell_fast_hash(input, output, input_len);
    else {
        if (cn_variant > 0 && input_len < 43)
            RETURN_EXCEPT("Argument must be 43 bytes for monero variant 1+");
        cryptonight_soft_shell_hash(input, output, input_len, cn_variant, scratchpad, iterations);
    }
    SET_BUFFER_RETURN(output, 32);
}
DECLARE_FUNC(chukwa) {
    DECLARE_SCOPE;
    // Chukwa Definitions
    const uint32_t hashlen = 32; // The length of the resulting hash in bytes
    const uint32_t saltlen = 16; // The length of our salt in bytes
    const uint32_t threads = 1; // How many threads to use at once
    const uint32_t iters = 3; // How many iterations we perform as part of our slow-hash
    const uint32_t memory = 512; // This value is in KiB (0.5MB)
    if (args.Length() < 1)
        RETURN_EXCEPT("You must provide one argument.");
    Local<Object> target = args[0]->ToObject();
    if(!Buffer::HasInstance(target))
        RETURN_EXCEPT("Argument should be a buffer object.");
    char * input = Buffer::Data(target);
    char output[32];
    uint32_t input_len = Buffer::Length(target);
    uint8_t salt[saltlen];
    std::memcpy(salt, input, sizeof(salt));
    argon2id_hash_raw(iters, memory, threads, input, input_len, salt, saltlen, output, hashlen);
    SET_BUFFER_RETURN(output, 32);
}
DECLARE_FUNC(boolberry) {
    DECLARE_SCOPE;
    if (args.Length() < 2)
        RETURN_EXCEPT("You must provide two arguments.");
    Local<Object> target = args[0]->ToObject();
    Local<Object> target_spad = args[1]->ToObject();
    uint32_t height = 1;
    if(!Buffer::HasInstance(target))
        RETURN_EXCEPT("Argument 1 should be a buffer object.");
    if(!Buffer::HasInstance(target_spad))
        RETURN_EXCEPT("Argument 2 should be a buffer object.");
    if(args.Length() >= 3) {
        if(args[2]->IsUint32())
            height = args[2]->Uint32Value();
        else
            RETURN_EXCEPT("Argument 3 should be an unsigned integer.");
    }
    char * input = Buffer::Data(target);
    char * scratchpad = Buffer::Data(target_spad);
    char output[32];
    uint32_t input_len = Buffer::Length(target);
    uint64_t spad_len = Buffer::Length(target_spad);
    boolberry_hash(input, input_len, scratchpad, spad_len, output, height);
    SET_BUFFER_RETURN(output, 32);
}

// Ethereum share submission methods
DECLARE_FUNC(ethSubmitHash) {
    DECLARE_SCOPE;
    
    if (args.Length() < 3)
        RETURN_EXCEPT("You must provide header hash, nonce and mix hash");
        
    Local<Object> header_hash = args[0]->ToObject();
    Local<Object> nonce = args[1]->ToObject();
    Local<Object> mix_hash = args[2]->ToObject();
    
    if(!Buffer::HasInstance(header_hash) || !Buffer::HasInstance(nonce) || !Buffer::HasInstance(mix_hash))
        RETURN_EXCEPT("Arguments should be buffer objects.");
        
    char * header_hash_data = Buffer::Data(header_hash);
    char * nonce_data = Buffer::Data(nonce);
    char * mix_hash_data = Buffer::Data(mix_hash);
    
    char output[32];
    
    ethash_hash(header_hash_data, output, 32, 0);
    
    SET_BUFFER_RETURN(output, 32);
}

DECLARE_FUNC(ethSubmitWork) {
    DECLARE_SCOPE;
    
    if (args.Length() < 3)
        RETURN_EXCEPT("You must provide header, nonce and mixhash");
        
    Local<Object> header = args[0]->ToObject();
    Local<Object> nonce = args[1]->ToObject();
    Local<Object> mixhash = args[2]->ToObject();
    
    if(!Buffer::HasInstance(header) || !Buffer::HasInstance(nonce) || !Buffer::HasInstance(mixhash))
        RETURN_EXCEPT("Arguments should be buffer objects.");
        
    char * header_data = Buffer::Data(header);
    char * nonce_data = Buffer::Data(nonce);
    char * mixhash_data = Buffer::Data(mixhash);
    
    char output[32];
    
    ethash_hash(header_data, output, 32, 0);
    
    SET_BUFFER_RETURN(output, 32);
}

DECLARE_INIT(init) {
    NODE_SET_METHOD(exports, "bcrypt", bcrypt);
    NODE_SET_METHOD(exports, "blake", blake);
    NODE_SET_METHOD(exports, "boolberry", boolberry);
    NODE_SET_METHOD(exports, "c11", c11);
    NODE_SET_METHOD(exports, "cryptonight", cryptonight);
    NODE_SET_METHOD(exports, "cryptonightdark", cryptonightdark);
    NODE_SET_METHOD(exports, "cryptonight-dark", cryptonightdark);
    NODE_SET_METHOD(exports, "cryptonightdarklite", cryptonightdarklite);
    NODE_SET_METHOD(exports, "cryptonight-dark-lite", cryptonightdarklite);
    NODE_SET_METHOD(exports, "cryptonightfast", cryptonightfast);
    NODE_SET_METHOD(exports, "cryptonight-fast", cryptonightfast);
    NODE_SET_METHOD(exports, "cryptonightlite", cryptonightlite);
    NODE_SET_METHOD(exports, "cryptonight-lite", cryptonightlite);
    NODE_SET_METHOD(exports, "cryptonightturtle", cryptonightturtle);
    NODE_SET_METHOD(exports, "cryptonight-turtle", cryptonightturtle);
    NODE_SET_METHOD(exports, "cryptonightturtlelite", cryptonightturtlelite);
    NODE_SET_METHOD(exports, "cryptonight-turtle-lite", cryptonightturtlelite);
    NODE_SET_METHOD(exports, "cryptonightsoftshell", cryptonightsoftshell);
    NODE_SET_METHOD(exports, "cryptonight-soft-shell", cryptonightsoftshell);
    NODE_SET_METHOD(exports, "chukwa", chukwa);
    NODE_SET_METHOD(exports, "fresh", fresh);
    NODE_SET_METHOD(exports, "fugue", fugue);
    NODE_SET_METHOD(exports, "groestl", groestl);
    NODE_SET_METHOD(exports, "groestlmyriad", groestlmyriad);
    NODE_SET_METHOD(exports, "hefty1", hefty1);
    NODE_SET_METHOD(exports, "keccak", keccak);
    NODE_SET_METHOD(exports, "nist5", nist5);
    NODE_SET_METHOD(exports, "quark", quark);
    NODE_SET_METHOD(exports, "qubit", qubit);
    NODE_SET_METHOD(exports, "scrypt", scrypt);
    NODE_SET_METHOD(exports, "scryptjane", scryptjane);
    NODE_SET_METHOD(exports, "scryptn", scryptn);
    NODE_SET_METHOD(exports, "sha1", sha1);
    NODE_SET_METHOD(exports, "shavite3", shavite3);
    NODE_SET_METHOD(exports, "skein", skein);
    NODE_SET_METHOD(exports, "x11", x11);
    NODE_SET_METHOD(exports, "x13", x13);
    NODE_SET_METHOD(exports, "x15", x15);

    NODE_SET_METHOD(exports, "equihash", equihash_wrapper);
    NODE_SET_METHOD(exports, "yescrypt", yescrypt_wrapper);
    NODE_SET_METHOD(exports, "yespowerr16", yespowerr16_wrapper);
    NODE_SET_METHOD(exports, "xelishash", xelishash_wrapper);
    NODE_SET_METHOD(exports, "xelishash_v2", xelishash_v2_wrapper);
    NODE_SET_METHOD(exports, "yescryptR8", yescryptR8);
    NODE_SET_METHOD(exports, "yescryptR16", yescryptR16);
    NODE_SET_METHOD(exports, "yescryptR32", yescryptR32);
    NODE_SET_METHOD(exports, "meowpow", meowpow);
    
    // Register Ethereum methods
    NODE_SET_METHOD(exports, "ethash_submit_hash", ethSubmitHash);
    NODE_SET_METHOD(exports, "ethash_submit_work", ethSubmitWork);
    NODE_SET_METHOD(exports, "ethash", ethash);
    NODE_SET_METHOD(exports, "nexa", nexa_wrapper);
}



NODE_MODULE(multihashing, init)