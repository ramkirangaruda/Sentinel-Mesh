#pragma once
#include <cstddef>
#include <cstdint>

// Parameter set for the handshake, chosen at COMPILE time (one NIST level per
// firmware image). Paper decision (paper/decisions.md): KEM and signature are
// paired by NIST security level and there is no runtime level negotiation, so
// every measured handshake is one fixed, reproducible parameter set.
//
//   SENTINEL_PQC_LEVEL 1  ->  ML-KEM-512  + ML-DSA-44   (NIST level 1 / 2)
//   SENTINEL_PQC_LEVEL 3  ->  ML-KEM-768  + ML-DSA-65   (NIST level 3)   [default]
//
// Level 5 (ML-KEM-1024 + ML-DSA-87) is not offered: ML-DSA-87 signing does not
// fit the ESP32's heap/stack (paper/data/E1). Backend: vendored PQClean "clean" C.

#ifndef SENTINEL_PQC_LEVEL
#define SENTINEL_PQC_LEVEL 3
#endif

// PQClean api.h files carry no extern "C" guard.
extern "C" {
#if SENTINEL_PQC_LEVEL == 1
#  include "pqclean/ml-kem-512/api.h"
#  include "pqclean/ml-dsa-44/api.h"
#  define SM_KEM(name) PQCLEAN_MLKEM512_CLEAN_##name
#  define SM_SIG(name) PQCLEAN_MLDSA44_CLEAN_##name
#  define SM_PQC_KEM_NAME "ML-KEM-512"
#  define SM_PQC_SIG_NAME "ML-DSA-44"
#elif SENTINEL_PQC_LEVEL == 3
#  include "pqclean/ml-kem-768/api.h"
#  include "pqclean/ml-dsa-65/api.h"
#  define SM_KEM(name) PQCLEAN_MLKEM768_CLEAN_##name
#  define SM_SIG(name) PQCLEAN_MLDSA65_CLEAN_##name
#  define SM_PQC_KEM_NAME "ML-KEM-768"
#  define SM_PQC_SIG_NAME "ML-DSA-65"
#else
#  error "SENTINEL_PQC_LEVEL must be 1 or 3 (ML-DSA-87 does not fit the ESP32)"
#endif
} // extern "C"

namespace sentinel::pqc {

constexpr size_t KEM_PK_BYTES  = SM_KEM(CRYPTO_PUBLICKEYBYTES);
constexpr size_t KEM_SK_BYTES  = SM_KEM(CRYPTO_SECRETKEYBYTES);
constexpr size_t KEM_CT_BYTES  = SM_KEM(CRYPTO_CIPHERTEXTBYTES);
constexpr size_t KEM_SS_BYTES  = SM_KEM(CRYPTO_BYTES);
constexpr size_t SIG_PK_BYTES  = SM_SIG(CRYPTO_PUBLICKEYBYTES);
constexpr size_t SIG_SK_BYTES  = SM_SIG(CRYPTO_SECRETKEYBYTES);
constexpr size_t SIG_BYTES     = SM_SIG(CRYPTO_BYTES);

} // namespace sentinel::pqc
