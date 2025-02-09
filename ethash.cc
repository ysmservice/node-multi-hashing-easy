#include "ethash.h"
#include <node.h>
#include <node_buffer.h>
#include <v8.h>
#include <stdint.h>
#include <string.h>
#include <vector>
#include "sha3/sph_keccak.h"

#define ETHASH_EPOCH_LENGTH 30000
#define ETHASH_CACHE_ROUNDS 3
#define ETHASH_MIX_BYTES 128
#define ETHASH_HASH_BYTES 64
#define ETHASH_DATASET_PARENTS 256
#define ETHASH_CACHE_BYTES_INIT 1073741824
#define ETHASH_CACHE_BYTES_GROWTH 131072
#define ETHASH_DATASET_BYTES_INIT 1073741824
#define ETHASH_DATASET_BYTES_GROWTH 8388608

static std::vector<uint8_t> s_cache;
static uint32_t s_epoch = 0xFFFFFFFF;

bool ethash_init_epoch(uint32_t epoch_number) {
    if (epoch_number == s_epoch)
        return true;
        
    // Calculate cache size
    uint64_t cache_size = ETHASH_CACHE_BYTES_INIT + ETHASH_CACHE_BYTES_GROWTH * epoch_number;
    cache_size -= cache_size % ETHASH_HASH_BYTES;
    
    s_cache.resize(cache_size);
    
    // Generate seed hash
    uint8_t seed[32] = {0};
    for(uint32_t i = 0; i < epoch_number; ++i) {
        sph_keccak256_context ctx;
        sph_keccak256_init(&ctx);
        sph_keccak256(&ctx, seed, 32);
        sph_keccak256_close(&ctx, seed);
    }
    
    // Initialize cache
    memcpy(s_cache.data(), seed, 32);
    for(size_t i = 32; i < cache_size; i += 32) {
        sph_keccak256_context ctx;
        sph_keccak256_init(&ctx);
        sph_keccak256(&ctx, &s_cache[i - 32], 32);
        sph_keccak256_close(&ctx, &s_cache[i]);
    }
    
    // Cache RNG
    for(uint32_t r = 0; r < ETHASH_CACHE_ROUNDS; ++r) {
        for(size_t i = 0; i < cache_size; i += 32) {
            uint32_t idx = *reinterpret_cast<uint32_t*>(&s_cache[i]) % (cache_size / 32);
            uint8_t tmp[32];
            sph_keccak256_context ctx;
            sph_keccak256_init(&ctx);
            sph_keccak256(&ctx, &s_cache[idx * 32], 32);
            sph_keccak256_close(&ctx, tmp);
            for(uint32_t j = 0; j < 32; ++j)
                s_cache[i + j] ^= tmp[j];
        }
    }
    
    s_epoch = epoch_number;
    return true;
}

void ethash_get_epoch_data(uint32_t epoch_number, uint8_t* cache, uint8_t* dag) {
    if (epoch_number != s_epoch && !ethash_init_epoch(epoch_number))
        return;
        
    if (cache)
        memcpy(cache, s_cache.data(), s_cache.size());
}

void ethash_hash(const char* input, char* output, uint32_t len, uint32_t epoch_number) {
    if (epoch_number != s_epoch && !ethash_init_epoch(epoch_number)) {
        memset(output, 0, 32);
        return;
    }
    
    // Initial hash
    sph_keccak512_context ctx;
    uint8_t hash[64];
    sph_keccak512_init(&ctx);
    sph_keccak512(&ctx, input, len);
    sph_keccak512_close(&ctx, hash);
    
    // Mix with cache
    uint8_t mix[ETHASH_MIX_BYTES];
    memcpy(mix, hash, ETHASH_MIX_BYTES);
    
    for(uint32_t i = 0; i < ETHASH_DATASET_PARENTS; ++i) {
        uint32_t idx = ((uint32_t*)mix)[i % 32] % (s_cache.size() / ETHASH_MIX_BYTES);
        for(uint32_t j = 0; j < ETHASH_MIX_BYTES; ++j)
            mix[j] ^= s_cache[idx * ETHASH_MIX_BYTES + j];
            
        sph_keccak512_init(&ctx);
        sph_keccak512(&ctx, mix, ETHASH_MIX_BYTES);
        sph_keccak512_close(&ctx, mix);
    }
    
    // Final hash
    sph_keccak256_context ctx_final;
    sph_keccak256_init(&ctx_final);
    sph_keccak256(&ctx_final, mix, ETHASH_MIX_BYTES);
    sph_keccak256_close(&ctx_final, output);
}

bool ethash_verify(const char* header_hash, const char* mix_hash, uint64_t nonce, uint32_t epoch_number) {
    char input[72];
    memcpy(input, header_hash, 32);
    memcpy(input + 32, mix_hash, 32);
    memcpy(input + 64, &nonce, 8);
    
    char output[32];
    ethash_hash(input, output, 72, epoch_number);
    
    return memcmp(output, mix_hash, 32) == 0;
}

void init(v8::Handle<v8::Object> exports) {
    NODE_SET_METHOD(exports, "ethash_init_epoch", method_init_epoch);
    NODE_SET_METHOD(exports, "ethash_get_epoch_data", method_get_epoch_data);
    NODE_SET_METHOD(exports, "ethash_hash", method_hash);
    NODE_SET_METHOD(exports, "ethash_verify", method_verify);
    NODE_SET_METHOD(exports, "ethash_submit_hash", method_submit_hash);
    NODE_SET_METHOD(exports, "ethash_submit_work", method_submit_work);
}

void method_init_epoch(const v8::FunctionCallbackInfo<v8::Value>& args) {
    v8::Isolate* isolate = args.GetIsolate();
    
    if (args.Length() < 1) {
        isolate->ThrowException(v8::Exception::TypeError(
            v8::String::NewFromUtf8(isolate, "Wrong number of arguments")));
        return;
    }
    
    uint32_t epoch_number = args[0]->Uint32Value();
    bool result = ethash_init_epoch(epoch_number);
    
    args.GetReturnValue().Set(result);
}

void method_get_epoch_data(const v8::FunctionCallbackInfo<v8::Value>& args) {
    v8::Isolate* isolate = args.GetIsolate();
    
    if (args.Length() < 1) {
        isolate->ThrowException(v8::Exception::TypeError(
            v8::String::NewFromUtf8(isolate, "Wrong number of arguments")));
        return;
    }
    
    uint32_t epoch_number = args[0]->Uint32Value();
    
    if (!args[1]->IsObject() || !node::Buffer::HasInstance(args[1])) {
        isolate->ThrowException(v8::Exception::TypeError(
            v8::String::NewFromUtf8(isolate, "Second argument should be a buffer object.")));
        return;
    }
    
    uint8_t* cache = (uint8_t*)node::Buffer::Data(args[1]);
    ethash_get_epoch_data(epoch_number, cache, nullptr);
}

void method_hash(const v8::FunctionCallbackInfo<v8::Value>& args) {
    v8::Isolate* isolate = args.GetIsolate();
    
    if (args.Length() < 2) {
        isolate->ThrowException(v8::Exception::TypeError(
            v8::String::NewFromUtf8(isolate, "Wrong number of arguments")));
        return;
    }
    
    if (!args[0]->IsObject() || !node::Buffer::HasInstance(args[0])) {
        isolate->ThrowException(v8::Exception::TypeError(
            v8::String::NewFromUtf8(isolate, "First argument should be a buffer object.")));
        return;
    }
    
    char* input = node::Buffer::Data(args[0]);
    size_t input_len = node::Buffer::Length(args[0]);
    uint32_t epoch_number = args[1]->Uint32Value();
    
    char output[32];
    ethash_hash(input, output, input_len, epoch_number);
    
    v8::Local<v8::Value> returnValue = node::Buffer::Copy(
        isolate, 
        output,
        32).ToLocalChecked();
        
    args.GetReturnValue().Set(returnValue);
}

void method_verify(const v8::FunctionCallbackInfo<v8::Value>& args) {
    v8::Isolate* isolate = args.GetIsolate();
    
    if (args.Length() < 4) {
        isolate->ThrowException(v8::Exception::TypeError(
            v8::String::NewFromUtf8(isolate, "Wrong number of arguments")));
        return;
    }
    
    if (!args[0]->IsObject() || !node::Buffer::HasInstance(args[0]) ||
        !args[1]->IsObject() || !node::Buffer::HasInstance(args[1])) {
        isolate->ThrowException(v8::Exception::TypeError(
            v8::String::NewFromUtf8(isolate, "First two arguments should be buffer objects.")));
        return;
    }
    
    char* header_hash = node::Buffer::Data(args[0]);
    char* mix_hash = node::Buffer::Data(args[1]);
    uint64_t nonce = args[2]->NumberValue();
    uint32_t epoch_number = args[3]->Uint32Value();
    
    bool result = ethash_verify(header_hash, mix_hash, nonce, epoch_number);
    
    args.GetReturnValue().Set(result);
}
void ethash_submit_hash(const char* header_hash, const char* nonce, const char* mix_hash, char* output, uint32_t epoch_number) {
    char input[72];
    memcpy(input, header_hash, 32);
    memcpy(input + 32, mix_hash, 32);
    memcpy(input + 64, nonce, 8);
    
    ethash_hash(input, output, 72, epoch_number);
}

void ethash_submit_work(const char* header, const char* nonce, const char* mixhash, char* output, uint32_t epoch_number) {
    char input[72];
    memcpy(input, header, 32);
    memcpy(input + 32, mixhash, 32);
    memcpy(input + 64, nonce, 8);
    
    ethash_hash(input, output, 72, epoch_number);
}

void method_submit_hash(const v8::FunctionCallbackInfo<v8::Value>& args) {
    v8::Isolate* isolate = args.GetIsolate();
    
    if (args.Length() < 4) {
        isolate->ThrowException(v8::Exception::TypeError(
            v8::String::NewFromUtf8(isolate, "Wrong number of arguments")));
        return;
    }
    
    if (!args[0]->IsObject() || !node::Buffer::HasInstance(args[0]) ||
        !args[1]->IsObject() || !node::Buffer::HasInstance(args[1]) ||
        !args[2]->IsObject() || !node::Buffer::HasInstance(args[2])) {
        isolate->ThrowException(v8::Exception::TypeError(
            v8::String::NewFromUtf8(isolate, "First three arguments should be buffer objects.")));
        return;
    }
    
    char* header_hash = node::Buffer::Data(args[0]);
    char* nonce = node::Buffer::Data(args[1]);
    char* mix_hash = node::Buffer::Data(args[2]);
    uint32_t epoch_number = args[3]->Uint32Value();
    
    char output[32];
    ethash_submit_hash(header_hash, nonce, mix_hash, output, epoch_number);
    
    v8::Local<v8::Value> returnValue = node::Buffer::Copy(
        isolate,
        output,
        32).ToLocalChecked();
        
    args.GetReturnValue().Set(returnValue);
}

void method_submit_work(const v8::FunctionCallbackInfo<v8::Value>& args) {
    v8::Isolate* isolate = args.GetIsolate();
    
    if (args.Length() < 4) {
        isolate->ThrowException(v8::Exception::TypeError(
            v8::String::NewFromUtf8(isolate, "Wrong number of arguments")));
        return;
    }
    
    if (!args[0]->IsObject() || !node::Buffer::HasInstance(args[0]) ||
        !args[1]->IsObject() || !node::Buffer::HasInstance(args[1]) ||
        !args[2]->IsObject() || !node::Buffer::HasInstance(args[2])) {
        isolate->ThrowException(v8::Exception::TypeError(
            v8::String::NewFromUtf8(isolate, "First three arguments should be buffer objects.")));
        return;
    }
    
    char* header = node::Buffer::Data(args[0]);
    char* nonce = node::Buffer::Data(args[1]);
    char* mixhash = node::Buffer::Data(args[2]);
    uint32_t epoch_number = args[3]->Uint32Value();
    
    char output[32];
    ethash_submit_work(header, nonce, mixhash, output, epoch_number);
    
    v8::Local<v8::Value> returnValue = node::Buffer::Copy(
        isolate,
        output,
        32).ToLocalChecked();
        
    args.GetReturnValue().Set(returnValue);
}

NODE_MODULE(ethash, init)