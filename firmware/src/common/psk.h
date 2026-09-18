#pragma once
#include <cstdint>

// DEMO-ONLY pre-shared key for the HMAC-PSK handshake fallback
// (sentinel_proto/auth_fallback.h). All boards embed this identical 32-byte
// key, provisioned the same crude way real ML-DSA public keys would
// eventually be (a host script -> embedded header). This is NOT secure key
// management -- anyone with this repo's source has the key. Acceptable for
// a hackathon demo, explicitly not for production, same honesty-rule
// labelling as auth_fallback.h's own file header.

namespace sentinel {

constexpr uint8_t DEMO_PSK[32] = {
    'S','e','n','t','i','n','e','l','M','e','s','h','-','d','e','m',
    'o','-','p','s','k','-','n','o','t','-','s','e','c','u','r','e'
};

} // namespace sentinel
