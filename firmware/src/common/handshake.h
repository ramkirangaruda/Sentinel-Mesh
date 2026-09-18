#pragma once
#include <cstdint>
#include <cstddef>
#include "sentinel_proto/auth_fallback.h"

// Real 3-message handshake using the HMAC-PSK fallback (auth_fallback.h)
// instead of true post-quantum ML-KEM/ML-DSA -- see firmware/README.md's
// "Biggest open risk" and platformio.ini's wolfSSL comment for why: no
// board-based benchmark exists yet to confirm ML-DSA-44 fits, and wolfSSL
// conflicts with the Arduino-ESP32 core as currently configured. This is
// the project's own documented fallback for exactly that situation --
// NOT post-quantum, real symmetric-key authentication, clearly labelled.
//
// Roles: the GATEWAY is always the initiator (it's mains-powered and wants
// to open/refresh a session with the field node); the FIELD NODE is always
// the responder, protected by EnergyGate's admission control on every
// inbound HELLO before any of this handshake work runs (brief v4: "an
// attacker who simply keeps saying hello can flatten a field node's
// battery"). A real field node never sends a HELLO in this design -- if the
// gateway ever receives one claiming the field node's identity, that is by
// definition an impersonation attempt, not a protocol bug.
//
// Wire flow (A = gateway/initiator, B = field node/responder):
//   A -> B  HELLO     [nonce_a (4B) | tag_a = HMAC(PSK, A_id | nonce_a) (32B)]              = 36B
//   B -> A  RESPONSE  [nonce_a echo (4B) | nonce_b (4B) | tag_b = HMAC(PSK, B_id|na|nb) (32B)] = 40B
//   A -> B  CONFIRM   [nonce_b echo (4B) | tag_c = HMAC(PSK, A_id|na|nb) (32B)]              = 36B
//
// Once CONFIRM is verified by B (or RESPONSE is verified by A -- each side
// finalizes independently, right after it verifies the other side's last
// message), both sides:
//  - derive a 32-byte AES-256-GCM session key from both nonces (derive_session_key)
//  - record their own millis() as "session start" -- future header.time_ms
//    values are sent as "ms since session start", landing both sides in the
//    same logical clock domain so ReplayFilter's freshness check actually
//    means something, instead of comparing two independent, unsynchronized
//    board uptimes (which is why every packet showed up "stale" before this).

namespace sentinel::handshake {

constexpr size_t NONCE_LEN = 4;
constexpr size_t HELLO_LEN = NONCE_LEN + HMAC_TAG_LEN;                // 36
constexpr size_t RESPONSE_LEN = NONCE_LEN + NONCE_LEN + HMAC_TAG_LEN; // 40
constexpr size_t CONFIRM_LEN = NONCE_LEN + HMAC_TAG_LEN;              // 36

void write_u32(uint8_t* out, uint32_t v);
uint32_t read_u32(const uint8_t* in);

// Builds a HELLO payload into `out` (needs HELLO_LEN bytes free).
void build_hello(uint8_t self_id, uint32_t nonce_a, uint8_t* out);
// Verifies an inbound HELLO. Returns false on a bad/missing tag (wrong PSK,
// or truncated data) -- treat as a rejected/impersonated handshake attempt.
bool verify_hello(uint8_t claimed_sender_id, const uint8_t* in, size_t in_len, uint32_t& nonce_a_out);

void build_response(uint8_t self_id, uint32_t nonce_a, uint32_t nonce_b, uint8_t* out);
bool verify_response(uint8_t claimed_sender_id, uint32_t expected_nonce_a,
                      const uint8_t* in, size_t in_len, uint32_t& nonce_b_out);

void build_confirm(uint8_t self_id, uint32_t nonce_a, uint32_t nonce_b, uint8_t* out);
bool verify_confirm(uint8_t claimed_sender_id, uint32_t nonce_a, uint32_t expected_nonce_b,
                     const uint8_t* in, size_t in_len);

// Derives the shared 32-byte AES-256-GCM session key (available to both
// sides independently once each has both nonces).
void derive_session_key(uint32_t nonce_a, uint32_t nonce_b, uint8_t out_key[32]);

} // namespace sentinel::handshake
