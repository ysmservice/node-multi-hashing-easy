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
}

#include "boolberry.h"

using namespace node;
using namespace v8;

// ...既存のコードは変更なし...

DECLARE_CALLBACK(meowpow, meowpow_hash, 32);

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
    NODE_SET_METHOD(exports, "equihash", equihash);
    NODE_SET_METHOD(exports, "yescrypt", yescrypt);
    NODE_SET_METHOD(exports, "yespowerr16", yespowerr16);
    NODE_SET_METHOD(exports, "xelishash", xelishash);
    NODE_SET_METHOD(exports, "xelishash_v2", xelishash_v2);
    NODE_SET_METHOD(exports, "yescryptR8", yescryptR8);
    NODE_SET_METHOD(exports, "yescryptR16", yescryptR16);
    NODE_SET_METHOD(exports, "yescryptR32", yescryptR32);
    NODE_SET_METHOD(exports, "meowpow", meowpow);
}

NODE_MODULE(multihashing, init)