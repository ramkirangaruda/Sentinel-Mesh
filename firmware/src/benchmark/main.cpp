// SentinelMesh crypto benchmark — flash this to any ESP32-WROOM-32 board
// FIRST, before writing the real handshake. Measures ML-KEM-512/768/1024
// (keygen/encaps/decaps) and ML-DSA-44 (keygen/sign/verify) timing plus
// heap and stack cost, and prints a CSV block to Serial.
//
// This is flagged as the project's single biggest risk (see brief section
// "Handshake and encryption" + firmware prompt point 1): if ML-DSA-44
// doesn't fit ESP32's RAM/flash/time budget, the fallback is a pre-shared
// HMAC-SHA256 key for authentication instead of a PQC signature — labelled
// clearly below and reported alongside the PQC numbers so the team can
// decide quickly.
//
// Backend selection (build flag, see platformio.ini env:benchmark):
//   SENTINEL_PQC_BACKEND_WOLFSSL  (default, tried first)
//   SENTINEL_PQC_BACKEND_PQCLEAN  (fallback if wolfCrypt's PQC build
//                                  doesn't fit/compile for this target)
//
// STATUS (paper Phase 3 / E0): default backend is now PQClean's portable "clean"
// ML-KEM-512/768/1024 and ML-DSA-44/65/87, vendored in lib/pqclean/ (see its
// README.md for the commit and licence). It runs in a 64 KB-stack FreeRTOS task.
// NOT yet compiled for the ESP32 (the authoring sandbox could not download the
// PlatformIO toolchain). The vendored PQClean sources were verified on a host
// gcc (round trips + forged-signature rejection, see paper/data/E0/HOST_TEST.md).
// First step on real hardware: `pio run -e benchmark`, then flash and log.
// The wolfSSL path below is kept but unused and still unverified.
//
// (older note) written against the documented wolfCrypt ML-KEM (wc_KyberKey,
// historically "Kyber") and ML-DSA (wc_dilithium_key, historically
// "Dilithium") APIs and against PQClean's reference C API. NOT YET BUILD-
// VERIFIED on real hardware — no ESP32 toolchain or these libraries are
// available in the environment this was written in. Treat the numbers this
// prints as the ground truth once it's actually flashed; treat the code
// itself as "should compile, needs a first real build" per the brief's
// instruction to write code that compiles when boards aren't in hand yet.
// See firmware/README.md "Crypto benchmark: known risk / next step".

#include <Arduino.h>
#if defined(SENTINEL_BENCH_TRUE_RANDOM_NO_RADIO)
#include "bootloader_random.h"
#endif

#if !defined(SENTINEL_PQC_BACKEND_WOLFSSL) && !defined(SENTINEL_PQC_BACKEND_PQCLEAN)
#define SENTINEL_PQC_BACKEND_PQCLEAN 1   // default since paper Phase 3 (E0); see lib/pqclean/README.md
#endif

#if defined(SENTINEL_PQC_BACKEND_WOLFSSL)
  // wolfSSL wolfCrypt PQC. Requires building wolfSSL with Kyber/ML-KEM and
  // Dilithium/ML-DSA enabled (WOLFSSL_HAVE_KYBER, WOLFSSL_WC_KYBER,
  // HAVE_DILITHIUM — these are NOT on by default in the stock PlatformIO
  // wolfssl/wolfSSL package, a custom user_settings.h is very likely
  // needed; see README). If this whole block fails to compile, define
  // SENTINEL_PQC_BACKEND_PQCLEAN instead in platformio.ini and vendor
  // PQClean's ml-kem-512/768/1024 + ml-dsa-44 C sources into
  // lib/sentinel_proto/third_party/pqclean/ (not fetched here — no network
  // access to PQClean's repo from this environment).
  #include <wolfssl/options.h>
  #include <wolfssl/wolfcrypt/kyber.h>
  #include <wolfssl/wolfcrypt/dilithium.h>
  #include <wolfssl/wolfcrypt/random.h>
#elif defined(SENTINEL_PQC_BACKEND_PQCLEAN)
  extern "C" {
  #include "pqclean/ml-kem-512/api.h"
  #include "pqclean/ml-kem-768/api.h"
  #include "pqclean/ml-kem-1024/api.h"
  #include "pqclean/ml-dsa-44/api.h"
  #include "pqclean/ml-dsa-65/api.h"
  #include "pqclean/ml-dsa-87/api.h"
  }
#endif

// ---------------------------------------------------------------------
// Timing + resource measurement helpers
// ---------------------------------------------------------------------

struct BenchResult {
    const char* algo;
    const char* op;       // "keygen" | "encaps" | "decaps" | "sign" | "verify"
    uint32_t us;           // wall time, microseconds
    uint32_t heap_used;    // bytes: free heap before - free heap after (peak proxy)
    uint32_t stack_hwm;    // bytes of stack still FREE at its deepest use (higher = safer)
    bool ok;
};

static void print_result(const BenchResult& r) {
    // CSV: algo,op,us,heap_used_bytes,stack_hwm_bytes,ok
    Serial.printf("%s,%s,%lu,%lu,%lu,%s\n",
                  r.algo, r.op,
                  static_cast<unsigned long>(r.us),
                  static_cast<unsigned long>(r.heap_used),
                  static_cast<unsigned long>(r.stack_hwm),
                  r.ok ? "ok" : "FAIL");
}

static uint32_t stack_high_water_bytes() {
    // ESP-IDF's FreeRTOS port (Xtensa) uses a byte-sized StackType_t, so
    // uxTaskGetStackHighWaterMark already returns BYTES of stack that were
    // never used (stock FreeRTOS returns words). Do not multiply.
    return uxTaskGetStackHighWaterMark(nullptr);
}

// Runs `fn` once, measuring wall time and heap delta around it. Stack HWM
// is a running minimum for the whole sketch, sampled after the call.
template <typename Fn>
static BenchResult time_op(const char* algo, const char* op, Fn&& fn) {
    uint32_t heap_before = ESP.getFreeHeap();
    uint32_t t0 = micros();
    bool ok = fn();
    uint32_t t1 = micros();
    uint32_t heap_after = ESP.getFreeHeap();

    BenchResult r;
    r.algo = algo;
    r.op = op;
    r.us = t1 - t0;
    r.heap_used = (heap_before > heap_after) ? (heap_before - heap_after) : 0;
    r.stack_hwm = stack_high_water_bytes();
    r.ok = ok;
    return r;
}

// ---------------------------------------------------------------------
// wolfSSL backend
// ---------------------------------------------------------------------
#if defined(SENTINEL_PQC_BACKEND_WOLFSSL)

static WC_RNG g_rng;

static void bench_kyber_level(const char* name, int kyber_type) {
    KyberKey key;
    unsigned char pub[KYBER_MAX_PUB_KEY_SIZE];
    unsigned char priv[KYBER_MAX_PRIV_KEY_SIZE];
    unsigned char ct[KYBER_MAX_CIPHER_TEXT_SIZE];
    unsigned char ss_a[KYBER_SS_SZ];
    unsigned char ss_b[KYBER_SS_SZ];
    word32 pub_len = 0, priv_len = 0, ct_len = 0, ss_len = 0;

    auto r_keygen = time_op(name, "keygen", [&]() {
        if (wc_KyberKey_Init(kyber_type, &key, nullptr, INVALID_DEVID) != 0) return false;
        if (wc_KyberKey_MakeKey(&key, &g_rng) != 0) return false;
        wc_KyberKey_PublicKeySize(&key, &pub_len);
        wc_KyberKey_PrivateKeySize(&key, &priv_len);
        return wc_KyberKey_EncodePublicKey(&key, pub, pub_len) == 0 &&
               wc_KyberKey_EncodePrivateKey(&key, priv, priv_len) == 0;
    });
    print_result(r_keygen);

    auto r_encaps = time_op(name, "encaps", [&]() {
        wc_KyberKey_CipherTextSize(&key, &ct_len);
        wc_KyberKey_SharedSecretSize(&key, &ss_len);
        return wc_KyberKey_Encapsulate(&key, ct, ss_a, &g_rng) == 0;
    });
    print_result(r_encaps);

    auto r_decaps = time_op(name, "decaps", [&]() {
        return wc_KyberKey_Decapsulate(&key, ss_b, ct, ct_len) == 0;
    });
    print_result(r_decaps);

    bool ss_match = (memcmp(ss_a, ss_b, ss_len) == 0);
    Serial.printf("%s,shared_secret_match,,,,%s\n", name, ss_match ? "ok" : "FAIL");

    wc_KyberKey_Free(&key);
}

static void bench_dilithium_44() {
    dilithium_key key;
    unsigned char pub[DILITHIUM_ML_DSA_44_PUB_KEY_SIZE];
    unsigned char priv[DILITHIUM_ML_DSA_44_PRV_KEY_SIZE];
    unsigned char sig[DILITHIUM_ML_DSA_44_SIG_SIZE];
    word32 sig_len = sizeof(sig);
    const unsigned char msg[] = "SentinelMesh handshake benchmark message";
    word32 msg_len = sizeof(msg) - 1;
    int verify_ok = 0;

    auto r_keygen = time_op("ML-DSA-44", "keygen", [&]() {
        if (wc_dilithium_init(&key) != 0) return false;
        if (wc_dilithium_set_level(&key, WC_ML_DSA_44) != 0) return false;
        if (wc_dilithium_make_key(&key, &g_rng) != 0) return false;
        word32 pub_len = sizeof(pub), priv_len = sizeof(priv);
        return wc_dilithium_export_public(&key, pub, &pub_len) == 0 &&
               wc_dilithium_export_private(&key, priv, &priv_len) == 0;
    });
    print_result(r_keygen);

    auto r_sign = time_op("ML-DSA-44", "sign", [&]() {
        return wc_dilithium_sign_msg(msg, msg_len, sig, &sig_len, &key, &g_rng) == 0;
    });
    print_result(r_sign);

    auto r_verify = time_op("ML-DSA-44", "verify", [&]() {
        return wc_dilithium_verify_msg(sig, sig_len, msg, msg_len, &verify_ok, &key) == 0 &&
               verify_ok == 1;
    });
    print_result(r_verify);

    wc_dilithium_free(&key);
}

static void run_benchmarks() {
    wc_InitRng(&g_rng);
    bench_kyber_level("ML-KEM-512", KYBER512);
    bench_kyber_level("ML-KEM-768", KYBER768);
    bench_kyber_level("ML-KEM-1024", KYBER1024);
    bench_dilithium_44();
    wc_FreeRng(&g_rng);
}

#endif // SENTINEL_PQC_BACKEND_WOLFSSL

// ---------------------------------------------------------------------
// PQClean backend (fallback path if wolfCrypt's PQC config doesn't fit)
// ---------------------------------------------------------------------
#if defined(SENTINEL_PQC_BACKEND_PQCLEAN)

static void bench_mlkem(const char* name,
                         int (*keypair)(unsigned char*, unsigned char*),
                         int (*encaps)(unsigned char*, unsigned char*, const unsigned char*),
                         int (*decaps)(unsigned char*, const unsigned char*, const unsigned char*),
                         size_t pk_len, size_t sk_len, size_t ct_len, size_t ss_len) {
    static unsigned char pk[4096], sk[8192], ct[4096], ss_a[64], ss_b[64];

    auto r_keygen = time_op(name, "keygen", [&]() {
        return keypair(pk, sk) == 0;
    });
    print_result(r_keygen);
    vTaskDelay(1);

    auto r_encaps = time_op(name, "encaps", [&]() {
        return encaps(ct, ss_a, pk) == 0;
    });
    print_result(r_encaps);

    auto r_decaps = time_op(name, "decaps", [&]() {
        return decaps(ss_b, ct, sk) == 0;
    });
    print_result(r_decaps);

    bool match = memcmp(ss_a, ss_b, ss_len) == 0;
    Serial.printf("%s,shared_secret_match,,,,%s\n", name, match ? "ok" : "FAIL");
    (void)pk_len; (void)sk_len; (void)ct_len;
}

typedef int (*dsa_keypair_fn)(uint8_t*, uint8_t*);
typedef int (*dsa_sign_fn)(uint8_t*, size_t*, const uint8_t*, size_t, const uint8_t*);
typedef int (*dsa_verify_fn)(const uint8_t*, size_t, const uint8_t*, size_t, const uint8_t*);

// ML-DSA-87 is the largest set: pk 2592 B, sk 4896 B, sig 4627 B.
static void bench_mldsa(const char* name, dsa_keypair_fn keypair,
                        dsa_sign_fn sign, dsa_verify_fn verify) {
    static unsigned char pk[4096], sk[6144], sig[5120];
    const unsigned char msg[] = "SentinelMesh handshake benchmark message";
    size_t msg_len = sizeof(msg) - 1;
    size_t sig_len = 0;

    print_result(time_op(name, "keygen", [&]() { return keypair(pk, sk) == 0; }));
    vTaskDelay(1);
    print_result(time_op(name, "sign", [&]() {
        return sign(sig, &sig_len, msg, msg_len, sk) == 0;
    }));
    vTaskDelay(1);
    print_result(time_op(name, "verify", [&]() {
        return verify(sig, sig_len, msg, msg_len, pk) == 0;
    }));
    vTaskDelay(1);

    // Sanity: the same signature must FAIL on a different message.
    const unsigned char bad[] = "SentinelMesh handshake benchmark messagX";
    bool rejected = verify(sig, sig_len, bad, sizeof(bad) - 1, pk) != 0;
    Serial.printf("%s,forged_message_rejected,,,,%s\n", name, rejected ? "ok" : "FAIL");
    Serial.printf("%s,signature_bytes,%u,,,ok\n", name, static_cast<unsigned>(sig_len));
}

static void run_benchmarks() {
    wc_InitRng(&g_rng);
    bench_kyber_level("ML-KEM-512", KYBER512);
    bench_kyber_level("ML-KEM-768", KYBER768);
    bench_kyber_level("ML-KEM-1024", KYBER1024);
    bench_dilithium_44();
    wc_FreeRng(&g_rng);
}

#endif // SENTINEL_PQC_BACKEND_WOLFSSL

// ---------------------------------------------------------------------
// PQClean backend (fallback path if wolfCrypt's PQC config doesn't fit)
// ---------------------------------------------------------------------
#if defined(SENTINEL_PQC_BACKEND_PQCLEAN)

static void bench_mlkem(const char* name,
                         int (*keypair)(unsigned char*, unsigned char*),
                         int (*encaps)(unsigned char*, unsigned char*, const unsigned char*),
                         int (*decaps)(unsigned char*, const unsigned char*, const unsigned char*),
                         size_t pk_len, size_t sk_len, size_t ct_len, size_t ss_len) {
    static unsigned char pk[4096], sk[8192], ct[4096], ss_a[64], ss_b[64];

    auto r_keygen = time_op(name, "keygen", [&]() {
        return keypair(pk, sk) == 0;
    });
    print_result(r_keygen);
    vTaskDelay(1);

    auto r_encaps = time_op(name, "encaps", [&]() {
        return encaps(ct, ss_a, pk) == 0;
    });
    print_result(r_encaps);

    auto r_decaps = time_op(name, "decaps", [&]() {
        return decaps(ss_b, ct, sk) == 0;
    });
    print_result(r_decaps);

    bool match = memcmp(ss_a, ss_b, ss_len) == 0;
    Serial.printf("%s,shared_secret_match,,,,%s\n", name, match ? "ok" : "FAIL");
    (void)pk_len; (void)sk_len; (void)ct_len;
}

static void bench_mldsa44() {
    static unsigned char pk[2048], sk[4096], sig[4096];
    const unsigned char msg[] = "SentinelMesh handshake benchmark message";
    size_t msg_len = sizeof(msg) - 1;
    size_t sig_len = 0;

    auto r_keygen = time_op("ML-DSA-44", "keygen", [&]() {
        return PQCLEAN_MLDSA44_CLEAN_crypto_sign_keypair(pk, sk) == 0;
    });
    print_result(r_keygen);

    auto r_sign = time_op("ML-DSA-44", "sign", [&]() {
        return PQCLEAN_MLDSA44_CLEAN_crypto_sign_signature(sig, &sig_len, msg, msg_len, sk) == 0;
    });
    print_result(r_sign);

    auto r_verify = time_op("ML-DSA-44", "verify", [&]() {
        return PQCLEAN_MLDSA44_CLEAN_crypto_sign_verify(sig, sig_len, msg, msg_len, pk) == 0;
    });
    print_result(r_verify);
}

static void run_benchmarks() {
    bench_mlkem("ML-KEM-512",
                PQCLEAN_MLKEM512_CLEAN_crypto_kem_keypair,
                PQCLEAN_MLKEM512_CLEAN_crypto_kem_enc,
                PQCLEAN_MLKEM512_CLEAN_crypto_kem_dec,
                PQCLEAN_MLKEM512_CLEAN_CRYPTO_PUBLICKEYBYTES,
                PQCLEAN_MLKEM512_CLEAN_CRYPTO_SECRETKEYBYTES,
                PQCLEAN_MLKEM512_CLEAN_CRYPTO_CIPHERTEXTBYTES,
                PQCLEAN_MLKEM512_CLEAN_CRYPTO_BYTES);
    bench_mlkem("ML-KEM-768",
                PQCLEAN_MLKEM768_CLEAN_crypto_kem_keypair,
                PQCLEAN_MLKEM768_CLEAN_crypto_kem_enc,
                PQCLEAN_MLKEM768_CLEAN_crypto_kem_dec,
                PQCLEAN_MLKEM768_CLEAN_CRYPTO_PUBLICKEYBYTES,
                PQCLEAN_MLKEM768_CLEAN_CRYPTO_SECRETKEYBYTES,
                PQCLEAN_MLKEM768_CLEAN_CRYPTO_CIPHERTEXTBYTES,
                PQCLEAN_MLKEM768_CLEAN_CRYPTO_BYTES);
    bench_mlkem("ML-KEM-1024",
                PQCLEAN_MLKEM1024_CLEAN_crypto_kem_keypair,
                PQCLEAN_MLKEM1024_CLEAN_crypto_kem_enc,
                PQCLEAN_MLKEM1024_CLEAN_crypto_kem_dec,
                PQCLEAN_MLKEM1024_CLEAN_CRYPTO_PUBLICKEYBYTES,
                PQCLEAN_MLKEM1024_CLEAN_CRYPTO_SECRETKEYBYTES,
                PQCLEAN_MLKEM1024_CLEAN_CRYPTO_CIPHERTEXTBYTES,
                PQCLEAN_MLKEM1024_CLEAN_CRYPTO_BYTES);
    bench_mldsa("ML-DSA-44",
                PQCLEAN_MLDSA44_CLEAN_crypto_sign_keypair,
                PQCLEAN_MLDSA44_CLEAN_crypto_sign_signature,
                PQCLEAN_MLDSA44_CLEAN_crypto_sign_verify);
    bench_mldsa("ML-DSA-65",
                PQCLEAN_MLDSA65_CLEAN_crypto_sign_keypair,
                PQCLEAN_MLDSA65_CLEAN_crypto_sign_signature,
                PQCLEAN_MLDSA65_CLEAN_crypto_sign_verify);
    bench_mldsa("ML-DSA-87",
                PQCLEAN_MLDSA87_CLEAN_crypto_sign_keypair,
                PQCLEAN_MLDSA87_CLEAN_crypto_sign_signature,
                PQCLEAN_MLDSA87_CLEAN_crypto_sign_verify);
}

#endif // SENTINEL_PQC_BACKEND_PQCLEAN

// ---------------------------------------------------------------------
// Classical baseline: X25519 ECDH + ECDSA/P-256 sign-verify
// ---------------------------------------------------------------------
// Brief v2 deliverables checklist: "Performance benchmarking vs classical
// TLS: compare ML-KEM-512/768/1024 with X25519/ECDHE". Uses mbedtls, which
// ships with the ESP32 Arduino core unconditionally (no extra lib_dep),
// so this runs regardless of which PQC backend is selected above.
//
// Honesty note (brief v2's own "honesty rule", section 8): the brief's
// frame-size table names "X25519 + Ed25519" as the classical baseline.
// Classic mbedtls (the API bundled with older ESP-IDF/Arduino-ESP32) does
// not expose Ed25519 signing directly — that lands in mbedtls 3.x's PSA
// crypto API, which is toolchain/IDF-version dependent and not something
// this environment can verify. So this benchmark measures X25519 ECDH
// (a faithful match) plus ECDSA over P-256 as the classical *signature*
// stand-in, not true Ed25519. Swap in psa_crypto's Ed25519 call if the
// on-target mbedtls turns out to be 3.x with PSA enabled — say so in the
// pitch either way, per the brief's own rule.

#include <mbedtls/ecdh.h>
#include <mbedtls/ecdsa.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>

static void bench_classical_baseline() {
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    const char* pers = "sentinelmesh_bench";
    mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                           reinterpret_cast<const unsigned char*>(pers), strlen(pers));

    // --- X25519 ECDH ---
    mbedtls_ecdh_context ecdh_a, ecdh_b;
    mbedtls_ecdh_init(&ecdh_a);
    mbedtls_ecdh_init(&ecdh_b);
    unsigned char buf_a[32], buf_b[32], secret_a[32], secret_b[32];
    size_t olen = 0;

    auto r_keygen = time_op("X25519", "keygen", [&]() {
        if (mbedtls_ecdh_setup(&ecdh_a, MBEDTLS_ECP_DP_CURVE25519) != 0) return false;
        if (mbedtls_ecdh_setup(&ecdh_b, MBEDTLS_ECP_DP_CURVE25519) != 0) return false;
        if (mbedtls_ecdh_gen_public(&ecdh_a.MBEDTLS_PRIVATE(grp), &ecdh_a.MBEDTLS_PRIVATE(d),
                                     &ecdh_a.MBEDTLS_PRIVATE(Q), mbedtls_ctr_drbg_random, &ctr_drbg) != 0) return false;
        return mbedtls_ecdh_gen_public(&ecdh_b.MBEDTLS_PRIVATE(grp), &ecdh_b.MBEDTLS_PRIVATE(d),
                                        &ecdh_b.MBEDTLS_PRIVATE(Q), mbedtls_ctr_drbg_random, &ctr_drbg) == 0;
    });
    print_result(r_keygen);

    auto r_exchange = time_op("X25519", "ecdh_compute_shared", [&]() {
        if (mbedtls_ecdh_compute_shared(&ecdh_a.MBEDTLS_PRIVATE(grp), &ecdh_a.MBEDTLS_PRIVATE(z),
                                         &ecdh_b.MBEDTLS_PRIVATE(Q), &ecdh_a.MBEDTLS_PRIVATE(d),
                                         mbedtls_ctr_drbg_random, &ctr_drbg) != 0) return false;
        return mbedtls_ecdh_compute_shared(&ecdh_b.MBEDTLS_PRIVATE(grp), &ecdh_b.MBEDTLS_PRIVATE(z),
                                            &ecdh_a.MBEDTLS_PRIVATE(Q), &ecdh_b.MBEDTLS_PRIVATE(d),
                                            mbedtls_ctr_drbg_random, &ctr_drbg) == 0;
    });
    print_result(r_exchange);
    (void)buf_a; (void)buf_b; (void)secret_a; (void)secret_b; (void)olen;

    mbedtls_ecdh_free(&ecdh_a);
    mbedtls_ecdh_free(&ecdh_b);

    // --- ECDSA / P-256 (classical signature stand-in, see note above) ---
    mbedtls_ecdsa_context ecdsa;
    mbedtls_ecdsa_init(&ecdsa);
    unsigned char sig[MBEDTLS_ECDSA_MAX_LEN];
    size_t sig_len = 0;
    const unsigned char hash[32] = {0}; // stand-in for SHA-256(message)

    auto r_dsa_keygen = time_op("ECDSA-P256", "keygen", [&]() {
        return mbedtls_ecdsa_genkey(&ecdsa, MBEDTLS_ECP_DP_SECP256R1,
                                     mbedtls_ctr_drbg_random, &ctr_drbg) == 0;
    });
    print_result(r_dsa_keygen);

    auto r_dsa_sign = time_op("ECDSA-P256", "sign", [&]() {
        return mbedtls_ecdsa_write_signature(&ecdsa, MBEDTLS_MD_SHA256, hash, sizeof(hash),
                                              sig, sizeof(sig), &sig_len,
                                              mbedtls_ctr_drbg_random, &ctr_drbg) == 0;
    });
    print_result(r_dsa_sign);

    auto r_dsa_verify = time_op("ECDSA-P256", "verify", [&]() {
        return mbedtls_ecdsa_read_signature(&ecdsa, hash, sizeof(hash), sig, sig_len) == 0;
    });
    print_result(r_dsa_verify);

    mbedtls_ecdsa_free(&ecdsa);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
}

// ---------------------------------------------------------------------
// Arduino entry points
// ---------------------------------------------------------------------

// ML-DSA's reference code keeps large polynomial vectors on the stack, far
// more than Arduino's loopTask (about 8 KB). Everything runs in its own task
// with a big stack (size in BYTES on ESP32). If you see "Stack canary
// watchpoint triggered (pqc_bench)", raise BENCH_STACK_BYTES.
#ifndef BENCH_STACK_BYTES
#define BENCH_STACK_BYTES 65536
#endif

static void bench_task(void*) {
    Serial.println("SentinelMesh crypto benchmark");
    Serial.printf("cpu_mhz=%u backend=%s stack_bytes=%u free_heap_start=%lu\n",
                  static_cast<unsigned>(getCpuFrequencyMhz()),
#if defined(SENTINEL_PQC_BACKEND_PQCLEAN)
                  "pqclean",
#else
                  "wolfssl",
#endif
                  static_cast<unsigned>(BENCH_STACK_BYTES),
                  static_cast<unsigned long>(ESP.getFreeHeap()));
    Serial.println("algo,op,us,heap_used_bytes,stack_hwm_bytes,ok");

    run_benchmarks();
    bench_classical_baseline();

    Serial.println("--- done ---");
    Serial.printf("free_heap_after_all_runs=%lu min_free_stack_bytes=%lu\n",
                  static_cast<unsigned long>(ESP.getFreeHeap()),
                  static_cast<unsigned long>(uxTaskGetStackHighWaterMark(nullptr)));
    vTaskDelete(nullptr);
}

void setup() {
    Serial.begin(115200);
    delay(2000); // give the serial monitor time to attach
#if defined(SENTINEL_BENCH_TRUE_RANDOM_NO_RADIO)
    // esp_random() is only truly random while Wi-Fi/Bluetooth is on. This
    // benchmark runs with the radio off, so enable the ADC noise source
    // (build with -DSENTINEL_BENCH_TRUE_RANDOM_NO_RADIO). Timing is unaffected.
    bootloader_random_enable();
#endif
    xTaskCreatePinnedToCore(bench_task, "pqc_bench", BENCH_STACK_BYTES,
                            nullptr, 1, nullptr, 1);
}

void loop() {
    delay(60000); // nothing to do; the benchmark task prints results once
}
