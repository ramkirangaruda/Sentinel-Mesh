#pragma once
#include <cstdint>
#include <cstddef>
#include <vector>

// AES-256-GCM encrypt/decrypt for the DATA path, per brief v2 6.1: "sent in
// clear but authenticated by AES-GCM, so any change to it is detected" for
// the header (passed as AAD here), with the payload itself encrypted.
// Built on mbedtls (bundled with the ESP32 Arduino core, same dependency
// auth_fallback.h already uses for HMAC) -- no extra lib_dep needed.

namespace sentinel::aead {

constexpr size_t GCM_TAG_LEN = 16;
constexpr size_t GCM_NONCE_LEN = 12; // mbedtls GCM's standard nonce size

// Packs the documented nonce scheme (packet.h: "nonce = sender||epoch||seq,
// padded to the cipher's nonce size") into a full 12-byte GCM nonce:
// 1B sender + 2B epoch + 4B seq = 7 real bytes, zero-padded to 12.
void build_nonce(uint8_t sender, uint16_t epoch, uint32_t seq, uint8_t out[GCM_NONCE_LEN]);

// Encrypts `plaintext` under `key` (32 bytes) with `nonce` (12 bytes, must
// never repeat under the same key) and `aad` (the packet header bytes,
// authenticated but not encrypted). Appends the 16-byte tag to the output.
// Returns false on an mbedtls error.
bool encrypt(const uint8_t key[32], const uint8_t nonce[GCM_NONCE_LEN],
             const uint8_t* aad, size_t aad_len,
             const uint8_t* plaintext, size_t plaintext_len,
             std::vector<uint8_t>& out_ciphertext_and_tag);

// Decrypts + verifies. `in_len` must be >= GCM_TAG_LEN. Returns false if the
// tag doesn't verify (tampered, wrong key, or wrong AAD) or on error --
// treat a false return as "reject this packet," never as partial plaintext.
bool decrypt(const uint8_t key[32], const uint8_t nonce[GCM_NONCE_LEN],
             const uint8_t* aad, size_t aad_len,
             const uint8_t* in, size_t in_len,
             std::vector<uint8_t>& out_plaintext);

} // namespace sentinel::aead
