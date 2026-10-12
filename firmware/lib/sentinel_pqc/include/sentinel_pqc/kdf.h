#pragma once
#include <cstddef>
#include <cstdint>

// Domain-separated hashing / KDF / MAC built on SHAKE256 (FIPS 202), which is
// already linked for ML-KEM/ML-DSA, so the handshake needs no extra hash code
// and runs identically on the host and the ESP32.
//
//   xof(out, label, parts) = SHAKE256( be16(len(label)) || label ||
//                                      for each part: be32(len) || bytes )
//
// Length-prefixing every field makes the encoding unambiguous. As a MAC the
// first part is the secret key (SHAKE256 is a PRF/MAC with a secret prefix;
// no length-extension issue because it is a sponge).

namespace sentinel::pqc {

struct Part {
    const uint8_t* p;
    size_t n;
};

void xof(uint8_t* out, size_t out_len, const char* label, const Part* parts, size_t n_parts);

// Constant-time equality for tags.
bool ct_equal(const uint8_t* a, const uint8_t* b, size_t n);

} // namespace sentinel::pqc
