#pragma once
#include <cstddef>
#include <cstdint>
#include "sentinel_pqc/pqc_params.h"
#include "sentinel_pqc/kdf.h"

// SentinelMesh post-quantum 3-message handshake (Phase 6).
//
//   I = initiator (gateway, mains powered)      R = responder (field-1, battery)
//
//   I -> R  HELLO     cookie(8) | nonce_i(16) | kem_pk | sig_I
//   R -> I  RESPONSE  nonce_i(16) | nonce_r(16) | kem_ct | sig_R
//   I -> R  CONFIRM   nonce_r(16) | tag(32)
//
// Authentication is by static ML-DSA keys (provisioned, see tools/gen_demo_keys.c);
// key agreement is an ephemeral ML-KEM. The cookie is OUTSIDE the signed
// transcript on purpose: after a CHALLENGE the initiator re-sends the same signed
// HELLO with the cookie field filled in, so it does not sign twice.
//
//   th1  = xof("SMv1/th1", I_id, R_id, nonce_i, kem_pk)
//   sig_I signs "SMv1/hello" || th1
//   th2  = xof("SMv1/th2", th1, nonce_r, kem_ct)
//   sig_R signs "SMv1/resp" || th2 || R_id || I_id
//   keys = xof(96, "SMv1/keys", ss, th2) -> k_i2r | k_r2i | k_confirm
//   tag  = xof(32, "SMv1/confirm", k_confirm, th2)
//
// Session keys feed AES-256-GCM (header as AAD) in the DATA path.
//
// Not a formally verified protocol: it is a plain signed-KEM exchange with
// transcript binding and key confirmation. Say so in the paper.
//
// Pure functions over byte buffers: no radio, no Arduino, no heap. Callers
// own the state structs (they are several kB: allocate them statically, not
// on a task stack). Signing needs a large stack (see paper/decisions.md).

namespace sentinel::pqc {

constexpr size_t COOKIE_BYTES = 8;
constexpr size_t NONCE_BYTES  = 16;
constexpr size_t TAG_BYTES    = 32;
constexpr size_t KEY_BYTES    = 32;

constexpr size_t HELLO_LEN    = COOKIE_BYTES + NONCE_BYTES + KEM_PK_BYTES + SIG_BYTES;
constexpr size_t RESPONSE_LEN = NONCE_BYTES + NONCE_BYTES + KEM_CT_BYTES + SIG_BYTES;
constexpr size_t CONFIRM_LEN  = NONCE_BYTES + TAG_BYTES;

enum class Result : uint8_t {
    OK = 0,
    BAD_LENGTH,
    BAD_BINDING,    // echoed nonce does not match this exchange
    BAD_SIGNATURE,  // ML-DSA verify failed
    BAD_TAG,        // key-confirmation tag mismatch
    CRYPTO_ERROR,   // KEM / sign returned an error
    NO_STATE,
};
const char* result_name(Result r);

// The costly operations, so a caller can raise the energy-marker GPIO around
// exactly one of them (paper E2/E3) or time them.
enum class Phase : uint8_t { KEM_KEYGEN, SIG_SIGN, SIG_VERIFY, KEM_ENCAPS, KEM_DECAPS, KDF };
const char* phase_name(Phase p);
using PhaseHook = void (*)(Phase phase, bool begin, void* user);
struct Hooks {
    PhaseHook fn = nullptr;
    void* user = nullptr;
    void begin(Phase p) const { if (fn) fn(p, true, user); }
    void end(Phase p) const { if (fn) fn(p, false, user); }
};

struct SessionKeys {
    uint8_t k_i2r[KEY_BYTES];   // initiator -> responder
    uint8_t k_r2i[KEY_BYTES];   // responder -> initiator
};

struct InitiatorState {
    bool valid = false;
    uint8_t kem_pk[KEM_PK_BYTES];
    uint8_t kem_sk[KEM_SK_BYTES];
    uint8_t nonce_i[NONCE_BYTES];
    uint8_t th1[32];
};

struct ResponderState {
    bool valid = false;
    uint8_t nonce_i[NONCE_BYTES];
    uint8_t nonce_r[NONCE_BYTES];
    uint8_t th2[32];
    uint8_t k_confirm[KEY_BYTES];
    SessionKeys keys;
};

// --- initiator --------------------------------------------------------------

// Generates the ephemeral KEM key, a fresh nonce, signs, and writes HELLO_LEN
// bytes to `out` with a zero cookie.
Result initiator_make_hello(InitiatorState& st, uint8_t self_id, uint8_t peer_id,
                            const uint8_t* self_sig_sk, const Hooks& hooks,
                            uint8_t out[HELLO_LEN]);

// Writes the cookie echo (from a CHALLENGE) into an already built HELLO.
void hello_set_cookie(uint8_t hello[HELLO_LEN], const uint8_t cookie[COOKIE_BYTES]);

// Verifies RESPONSE, decapsulates, derives keys, writes CONFIRM.
Result initiator_handle_response(InitiatorState& st, uint8_t self_id, uint8_t peer_id,
                                 const uint8_t* peer_sig_pk, const uint8_t* in, size_t in_len,
                                 const Hooks& hooks, SessionKeys& keys,
                                 uint8_t confirm_out[CONFIRM_LEN]);

// --- responder --------------------------------------------------------------

// Verifies the initiator's signature, encapsulates, signs and writes
// RESPONSE_LEN bytes to `response_out`. This is the expensive call: the hooks
// let the caller mark VERIFY / ENCAPS / SIGN separately. A forged HELLO costs
// only the VERIFY phase.
Result responder_handle_hello(ResponderState& st, uint8_t self_id, uint8_t peer_id,
                              const uint8_t* peer_sig_pk, const uint8_t* self_sig_sk,
                              const uint8_t* in, size_t in_len, const Hooks& hooks,
                              uint8_t response_out[RESPONSE_LEN]);

Result responder_handle_confirm(ResponderState& st, const uint8_t* in, size_t in_len,
                                SessionKeys& keys);

} // namespace sentinel::pqc
