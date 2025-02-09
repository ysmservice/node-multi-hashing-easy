{
    "targets": [
        {
            "target_name": "multihashing",
            "sources": [
                "multihashing.cc",
                "yespowerr16.c",
                "yescryptR8.c",
                "yescryptR16.c",
                "yescryptR32.c",
                "progpow.cc",
                "meowpow.cc",
                "bcrypt.c",
                "blake.c",
                "boolberry.cc",
                "c11.c",
                "cryptonight.c",
                "cryptonight_dark.c",
                "cryptonight_dark_lite.c",
                "cryptonight_fast.c",
                "cryptonight_lite.c",
                "cryptonight_turtle.c",
                "cryptonight_turtle_lite.c",
                "cryptonight_soft_shell.c",
                "fresh.c",
                "fugue.c",
                "groestl.c",
                "hefty1.c",
                "keccak.c",
                "nist5.c",
                "quark.c",
                "qubit.c",
                "scryptjane.c",
                "scryptn.c",
                "sha1.c",
                "shavite3.c",
                "skein.c",
                "x11.c",
                "x13.c",
                "x15.c",
                "equihash.cc",
                "yescrypt.c",
                "verushash.c",
                "ghostrider.c",
                "beamhash.c",
                "verthash.c",
                "heavyhash.c",
                "x16rv2.c",
                "ethash.cc",
                "xelishash.cc",
                "handshake.cc",
                "kaspa.cc",
                "zano.cc",
                "sha3/sph_hefty1.c",
                "sha3/sph_fugue.c",
                "sha3/aes_helper.c",
                "sha3/sph_blake.c",
                "sha3/sph_bmw.c",
                "sha3/sph_cubehash.c",
                "sha3/sph_echo.c",
                "sha3/sph_groestl.c",
                "sha3/sph_jh.c",
                "sha3/sph_keccak.c",
                "sha3/sph_luffa.c",
                "sha3/sph_shavite.c",
                "sha3/sph_simd.c",
                "sha3/sph_skein.c",
                "sha3/sph_whirlpool.c",
                "sha3/sph_shabal.c",
                "sha3/hamsi.c",
                "crypto/oaes_lib.c",
                "crypto/c_keccak.c",
                "crypto/c_groestl.c",
                "crypto/c_blake256.c",
                "crypto/c_jh.c",
                "crypto/c_skein.c",
                "crypto/hash.c",
                "crypto/aesb.c",
                "crypto/wild_keccak.cpp",
                "argon2/src/argon2.c",
                "argon2/src/core.c",
                "argon2/src/encoding.c",
                "argon2/src/ref.c",
                "argon2/src/thread.c",
                "argon2/src/blake2/blake2b.c",
                "blake3/blake3.c",
                "blake3/blake3_dispatch.c",
                "blake3/blake3_portable.c",
                "blake3/blake3_sse2.c",
                "blake3/blake3_sse41.c",
                "blake3/blake3_avx2.c",
                "blake3/blake3_avx512.c",
                "chacha20/chacha20.c",
                "chacha20/chacha20_dispatch.c",
                "chacha20/chacha20_sse2.c",
                "chacha20/chacha20_avx2.c"
            ],
            "include_dirs": [
                "crypto",
                "argon2/include",
                "blake3",
                "chacha20",
                "ethash/include",
                "ethash/lib"
            ],
            "cflags_cc": [
                "-std=c++0x",
                "-maes",
                "-msse2",
                "-msse4.1",
                "-mavx2",
                "-Wno-missing-field-initializers",
                "-Wno-unused-function",
                "-Wno-unused-const-variable",
                "-Wno-unused-private-field",
                "-Wno-unused-but-set-variable"
            ],
            "cflags": [
                "-maes",
                "-msse2",
                "-msse4.1",
                "-mavx2"
            ],
            "xcode_settings": {
                "OTHER_CFLAGS": [
                    "-maes",
                    "-msse2",
                    "-msse4.1",
                    "-mavx2",
                    "-Wno-missing-field-initializers",
                    "-Wno-unused-function",
                    "-Wno-unused-const-variable",
                    "-Wno-unused-private-field",
                    "-Wno-unused-but-set-variable"
                ]
            }
        }
    ]
}
