#include "sentinel_pqc/pqc_handshake.h"
#include <cstring>
extern "C" {
#include "randombytes.h"
}

namespace sentinel::pqc {

const char* result_name(Result r) {
    switch (r) {
        case Result::OK: return "ok";
        case Result::BAD_LENGTH: return "bad_length";
        case Result::BAD_BINDING: return "bad_binding";
        case Result::BAD_SIGNATURE: return "bad_signature";
        case Result::BAD_TAG: return "bad_tag";
        case Result::CRYPTO_ERROR: return "crypto_error";
        case Result::NO_STATE: return "no_state";
    }
    return "?";
}

const char* phase_name(Phase p) {
    switch (p) {
        case Phase::KEM_KEYGEN: return "kem_keygen";
        case Phase::SIG_SIGN: return "sig_sign";
        case Phase::SIG_VERIFY: return "sig_verify";
        case Phase::KEM_ENCAPS: return "kem_encaps";
        case Phase::KEM_DECAPS: return "kem_decaps";
        case Phase::KDF: return "kdf";
    }
    return "?";
}

namespace {

// Message layouts (offsets into the payloads).
constexpr size_t H_COOKIE = 0;
constexpr size_t H_NONCE = COOKIE_BYTES;
constexpr size_t H_PK = H_NONCE + NONCE_BYTES;
constexpr size_t H_SIG = H_PK + KEM_PK_BYTES;

constexpr size_t R_NONCE_I = 0;
constexpr size_t R_NONCE_R = NONCE_BYTES;
constexpr size_t R_CT = R_NONCE_R + NONCE_BYTES;
constexpr size_t R_SIG = R_CT + KEM_CT_BYTES;

// Signed messages are short fixed-size strings (a label plus a digest), so a
// signature never depends on the multi-kB body directly.
constexpr char L_HELLO[] = "SMv1/hello";
constexpr char L_RESP[] = "SMv1/resp";

void th1_of(uint8_t th1[32], uint8_t i_id, uint8_t r_id, const uint8_t* nonce_i, const uint8_t* kem_pk) {
    const Part parts[] = {{&i_id, 1}, {&r_id, 1}, {nonce_i, NONCE_BYTES}, {kem_pk, KEM_PK_BYTES}};
    xof(th1, 32, "SMv1/th1", parts, 4);
}

void th2_of(uint8_t th2[32], const uint8_t th1[32], const uint8_t* nonce_r, const uint8_t* ct) {
    const Part parts[] = {{th1, 32}, {nonce_r, NONCE_BYTES}, {ct, KEM_CT_BYTES}};
    xof(th2, 32, "SMv1/th2", parts, 3);
}

// sig message = label || th (|| ids for the response)
size_t hello_sign_msg(uint8_t* m, const uint8_t th1[32]) {
    size_t n = sizeof(L_HELLO) - 1;
    memcpy(m, L_HELLO, n);
    memcpy(m + n, th1, 32);
    return n + 32;
}

size_t resp_sign_msg(uint8_t* m, const uint8_t th2[32], uint8_t r_id, uint8_t i_id) {
    size_t n = sizeof(L_RESP) - 1;
    memcpy(m, L_RESP, n);
    memcpy(m + n, th2, 32);
    m[n + 32] = r_id;
    m[n + 33] = i_id;
    return n + 34;
}

void derive(const uint8_t* ss, const uint8_t th2[32], uint8_t k_confirm[KEY_BYTES], SessionKeys& keys) {
    uint8_t okm[3 * KEY_BYTES];
    const Part parts[] = {{ss, KEM_SS_BYTES}, {th2, 32}};
    xof(okm, sizeof(okm), "SMv1/keys", parts, 2);
    memcpy(keys.k_i2r, okm, KEY_BYTES);
    memcpy(keys.k_r2i, okm + KEY_BYTES, KEY_BYTES);
    memcpy(k_confirm, okm + 2 * KEY_BYTES, KEY_BYTES);
    memset(okm, 0, sizeof(okm));
}

void confirm_tag(uint8_t tag[TAG_BYTES], const uint8_t k_confirm[KEY_BYTES], const uint8_t th2[32]) {
    const Part parts[] = {{k_confirm, KEY_BYTES}, {th2, 32}};
    xof(tag, TAG_BYTES, "SMv1/confirm", parts, 2);
}

} // namespace

// ----------------------------------------------------------------------------
// initiator
// ----------------------------------------------------------------------------

Result initiator_make_hello(InitiatorState& st, uint8_t self_id, uint8_t peer_id,
                            const uint8_t* self_sig_sk, const Hooks& hooks,
                            uint8_t out[HELLO_LEN]) {
    st.valid = false;
    hooks.begin(Phase::KEM_KEYGEN);
    int rc = SM_KEM(crypto_kem_keypair)(st.kem_pk, st.kem_sk);
    hooks.end(Phase::KEM_KEYGEN);
    if (rc != 0) return Result::CRYPTO_ERROR;
    if (randombytes(st.nonce_i, NONCE_BYTES) != 0) return Result::CRYPTO_ERROR;

    th1_of(st.th1, self_id, peer_id, st.nonce_i, st.kem_pk);

    uint8_t m[sizeof(L_HELLO) - 1 + 32];
    size_t mlen = hello_sign_msg(m, st.th1);
    size_t siglen = 0;
    hooks.begin(Phase::SIG_SIGN);
    rc = SM_SIG(crypto_sign_signature)(out + H_SIG, &siglen, m, mlen, self_sig_sk);
    hooks.end(Phase::SIG_SIGN);
    if (rc != 0 || siglen != SIG_BYTES) return Result::CRYPTO_ERROR;

    memset(out + H_COOKIE, 0, COOKIE_BYTES);
    memcpy(out + H_NONCE, st.nonce_i, NONCE_BYTES);
    memcpy(out + H_PK, st.kem_pk, KEM_PK_BYTES);
    st.valid = true;
    return Result::OK;
}

void hello_set_cookie(uint8_t hello[HELLO_LEN], const uint8_t cookie[COOKIE_BYTES]) {
    memcpy(hello + H_COOKIE, cookie, COOKIE_BYTES);
}

Result initiator_handle_response(InitiatorState& st, uint8_t self_id, uint8_t peer_id,
                                 const uint8_t* peer_sig_pk, const uint8_t* in, size_t in_len,
                                 const Hooks& hooks, SessionKeys& keys,
                                 uint8_t confirm_out[CONFIRM_LEN]) {
    if (!st.valid) return Result::NO_STATE;
    if (in_len != RESPONSE_LEN) return Result::BAD_LENGTH;
    if (!ct_equal(in + R_NONCE_I, st.nonce_i, NONCE_BYTES)) return Result::BAD_BINDING;

    const uint8_t* nonce_r = in + R_NONCE_R;
    const uint8_t* ct = in + R_CT;

    uint8_t th2[32];
    th2_of(th2, st.th1, nonce_r, ct);

    uint8_t m[sizeof(L_RESP) - 1 + 34];
    size_t mlen = resp_sign_msg(m, th2, peer_id, self_id);
    hooks.begin(Phase::SIG_VERIFY);
    int rc = SM_SIG(crypto_sign_verify)(in + R_SIG, SIG_BYTES, m, mlen, peer_sig_pk);
    hooks.end(Phase::SIG_VERIFY);
    if (rc != 0) return Result::BAD_SIGNATURE;

    uint8_t ss[KEM_SS_BYTES];
    hooks.begin(Phase::KEM_DECAPS);
    rc = SM_KEM(crypto_kem_dec)(ss, ct, st.kem_sk);
    hooks.end(Phase::KEM_DECAPS);
    if (rc != 0) return Result::CRYPTO_ERROR;

    uint8_t k_confirm[KEY_BYTES];
    hooks.begin(Phase::KDF);
    derive(ss, th2, k_confirm, keys);
    memcpy(confirm_out, nonce_r, NONCE_BYTES);
    confirm_tag(confirm_out + NONCE_BYTES, k_confirm, th2);
    hooks.end(Phase::KDF);

    memset(ss, 0, sizeof(ss));
    memset(k_confirm, 0, sizeof(k_confirm));
    memset(st.kem_sk, 0, sizeof(st.kem_sk)); // ephemeral: wipe as soon as it has been used
    st.valid = false;
    return Result::OK;
}

// ----------------------------------------------------------------------------
// responder
// ----------------------------------------------------------------------------

Result responder_handle_hello(ResponderState& st, uint8_t self_id, uint8_t peer_id,
                              const uint8_t* peer_sig_pk, const uint8_t* self_sig_sk,
                              const uint8_t* in, size_t in_len, const Hooks& hooks,
                              uint8_t response_out[RESPONSE_LEN]) {
    st.valid = false;
    if (in_len != HELLO_LEN) return Result::BAD_LENGTH;

    const uint8_t* nonce_i = in + H_NONCE;
    const uint8_t* kem_pk = in + H_PK;

    uint8_t th1[32];
    th1_of(th1, peer_id, self_id, nonce_i, kem_pk);

    uint8_t m[sizeof(L_RESP) - 1 + 34];
    size_t mlen = hello_sign_msg(m, th1);
    hooks.begin(Phase::SIG_VERIFY);
    int rc = SM_SIG(crypto_sign_verify)(in + H_SIG, SIG_BYTES, m, mlen, peer_sig_pk);
    hooks.end(Phase::SIG_VERIFY);
    if (rc != 0) return Result::BAD_SIGNATURE;

    memcpy(st.nonce_i, nonce_i, NONCE_BYTES);
    if (randombytes(st.nonce_r, NONCE_BYTES) != 0) return Result::CRYPTO_ERROR;

    uint8_t ss[KEM_SS_BYTES];
    uint8_t* ct = response_out + R_CT;
    hooks.begin(Phase::KEM_ENCAPS);
    rc = SM_KEM(crypto_kem_enc)(ct, ss, kem_pk);
    hooks.end(Phase::KEM_ENCAPS);
    if (rc != 0) return Result::CRYPTO_ERROR;

    th2_of(st.th2, th1, st.nonce_r, ct);

    mlen = resp_sign_msg(m, st.th2, self_id, peer_id);
    size_t siglen = 0;
    hooks.begin(Phase::SIG_SIGN);
    rc = SM_SIG(crypto_sign_signature)(response_out + R_SIG, &siglen, m, mlen, self_sig_sk);
    hooks.end(Phase::SIG_SIGN);
    if (rc != 0 || siglen != SIG_BYTES) return Result::CRYPTO_ERROR;

    hooks.begin(Phase::KDF);
    derive(ss, st.th2, st.k_confirm, st.keys);
    hooks.end(Phase::KDF);
    memset(ss, 0, sizeof(ss));

    memcpy(response_out + R_NONCE_I, st.nonce_i, NONCE_BYTES);
    memcpy(response_out + R_NONCE_R, st.nonce_r, NONCE_BYTES);
    st.valid = true;
    return Result::OK;
}

Result responder_handle_confirm(ResponderState& st, const uint8_t* in, size_t in_len,
                                SessionKeys& keys) {
    if (!st.valid) return Result::NO_STATE;
    if (in_len != CONFIRM_LEN) return Result::BAD_LENGTH;
    if (!ct_equal(in, st.nonce_r, NONCE_BYTES)) return Result::BAD_BINDING;
    uint8_t tag[TAG_BYTES];
    confirm_tag(tag, st.k_confirm, st.th2);
    if (!ct_equal(tag, in + NONCE_BYTES, TAG_BYTES)) return Result::BAD_TAG;
    keys = st.keys;
    memset(&st.keys, 0, sizeof(st.keys));
    memset(st.k_confirm, 0, sizeof(st.k_confirm));
    st.valid = false;
    return Result::OK;
}

} // namespace sentinel::pqc
