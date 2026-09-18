// ESP32-only: depends on auth_fallback.h, which itself only compiles under
// ARDUINO (needs mbedtls). Mirrors that guard so this is safe to glob on
// host builds too.
#ifdef ARDUINO

#include "common/handshake.h"
#include "common/psk.h"
#include <cstring>

namespace sentinel::handshake {

void write_u32(uint8_t* out, uint32_t v) {
    out[0] = static_cast<uint8_t>(v >> 24);
    out[1] = static_cast<uint8_t>(v >> 16);
    out[2] = static_cast<uint8_t>(v >> 8);
    out[3] = static_cast<uint8_t>(v);
}

uint32_t read_u32(const uint8_t* in) {
    return (static_cast<uint32_t>(in[0]) << 24) | (static_cast<uint32_t>(in[1]) << 16) |
           (static_cast<uint32_t>(in[2]) << 8) | static_cast<uint32_t>(in[3]);
}

void build_hello(uint8_t self_id, uint32_t nonce_a, uint8_t* out) {
    write_u32(out, nonce_a);
    uint8_t msg[1 + NONCE_LEN];
    msg[0] = self_id;
    write_u32(msg + 1, nonce_a);
    HmacPskAuth(DEMO_PSK).sign(msg, sizeof(msg), out + NONCE_LEN);
}

bool verify_hello(uint8_t claimed_sender_id, const uint8_t* in, size_t in_len, uint32_t& nonce_a_out) {
    if (in_len < HELLO_LEN) return false;
    nonce_a_out = read_u32(in);
    uint8_t msg[1 + NONCE_LEN];
    msg[0] = claimed_sender_id;
    write_u32(msg + 1, nonce_a_out);
    return HmacPskAuth(DEMO_PSK).verify(msg, sizeof(msg), in + NONCE_LEN);
}

void build_response(uint8_t self_id, uint32_t nonce_a, uint32_t nonce_b, uint8_t* out) {
    write_u32(out, nonce_a);
    write_u32(out + NONCE_LEN, nonce_b);
    uint8_t msg[1 + NONCE_LEN + NONCE_LEN];
    msg[0] = self_id;
    write_u32(msg + 1, nonce_a);
    write_u32(msg + 1 + NONCE_LEN, nonce_b);
    HmacPskAuth(DEMO_PSK).sign(msg, sizeof(msg), out + NONCE_LEN + NONCE_LEN);
}

bool verify_response(uint8_t claimed_sender_id, uint32_t expected_nonce_a,
                      const uint8_t* in, size_t in_len, uint32_t& nonce_b_out) {
    if (in_len < RESPONSE_LEN) return false;
    uint32_t echoed_nonce_a = read_u32(in);
    if (echoed_nonce_a != expected_nonce_a) return false; // binds this RESPONSE to our HELLO
    nonce_b_out = read_u32(in + NONCE_LEN);
    uint8_t msg[1 + NONCE_LEN + NONCE_LEN];
    msg[0] = claimed_sender_id;
    write_u32(msg + 1, expected_nonce_a);
    write_u32(msg + 1 + NONCE_LEN, nonce_b_out);
    return HmacPskAuth(DEMO_PSK).verify(msg, sizeof(msg), in + NONCE_LEN + NONCE_LEN);
}

void build_confirm(uint8_t self_id, uint32_t nonce_a, uint32_t nonce_b, uint8_t* out) {
    write_u32(out, nonce_b);
    uint8_t msg[1 + NONCE_LEN + NONCE_LEN];
    msg[0] = self_id;
    write_u32(msg + 1, nonce_a);
    write_u32(msg + 1 + NONCE_LEN, nonce_b);
    HmacPskAuth(DEMO_PSK).sign(msg, sizeof(msg), out + NONCE_LEN);
}

bool verify_confirm(uint8_t claimed_sender_id, uint32_t nonce_a, uint32_t expected_nonce_b,
                     const uint8_t* in, size_t in_len) {
    if (in_len < CONFIRM_LEN) return false;
    uint32_t echoed_nonce_b = read_u32(in);
    if (echoed_nonce_b != expected_nonce_b) return false;
    uint8_t msg[1 + NONCE_LEN + NONCE_LEN];
    msg[0] = claimed_sender_id;
    write_u32(msg + 1, nonce_a);
    write_u32(msg + 1 + NONCE_LEN, expected_nonce_b);
    return HmacPskAuth(DEMO_PSK).verify(msg, sizeof(msg), in + NONCE_LEN);
}

void derive_session_key(uint32_t nonce_a, uint32_t nonce_b, uint8_t out_key[32]) {
    uint8_t msg[6 + NONCE_LEN + NONCE_LEN];
    memcpy(msg, "AESKEY", 6);
    write_u32(msg + 6, nonce_a);
    write_u32(msg + 6 + NONCE_LEN, nonce_b);
    // HMAC-SHA256's 32-byte output doubles as the AES-256 key directly --
    // no separate KDF needed for a demo-scoped derivation like this.
    HmacPskAuth(DEMO_PSK).sign(msg, sizeof(msg), out_key);
}

} // namespace sentinel::handshake

#endif // ARDUINO
