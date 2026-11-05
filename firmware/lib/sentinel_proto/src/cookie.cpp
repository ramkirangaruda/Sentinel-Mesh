#include "sentinel_proto/cookie.h"

namespace sentinel {

namespace {

// SplitMix64-style avalanche mix. Not a cryptographic MAC (see cookie.h) --
// just needs to spread (secret, sender, epoch, seq, time_window) across 64
// bits so an attacker can't predict the cookie without the secret, and a
// 1-bit input change flips roughly half the output bits.
inline uint64_t mix64(uint64_t x) {
    x += 0x9E3779B97F4A7C15ULL;
    x = (x ^ (x >> 30)) * 0xBF58476D1CE4E5B9ULL;
    x = (x ^ (x >> 27)) * 0x94D049BB133111EBULL;
    x = x ^ (x >> 31);
    return x;
}

// Folds the (epoch, seq) pair in before mixing with the rest, so the cookie answers for one
// exact HELLO (its header's epoch/seq), not "this sender, this window" (see cookie.h).
uint64_t compute(uint32_t secret, uint8_t sender, uint16_t epoch, uint32_t seq, uint32_t time_window) {
    uint64_t es = (static_cast<uint64_t>(epoch) << 32) ^ static_cast<uint64_t>(seq);
    uint64_t input = (static_cast<uint64_t>(secret) << 32) ^
                      (static_cast<uint64_t>(sender) << 24) ^
                      static_cast<uint64_t>(time_window);
    return mix64(input ^ mix64(es));
}

void write_cookie(uint64_t v, uint8_t out[COOKIE_LEN]) {
    for (size_t i = 0; i < COOKIE_LEN; ++i) {
        out[i] = static_cast<uint8_t>(v >> (8 * (COOKIE_LEN - 1 - i)));
    }
}

bool constant_time_equal(const uint8_t* a, const uint8_t* b, size_t len) {
    uint8_t diff = 0;
    for (size_t i = 0; i < len; ++i) diff |= static_cast<uint8_t>(a[i] ^ b[i]);
    return diff == 0;
}

} // namespace

void CookieChallenge::generate(uint8_t sender, uint16_t epoch, uint32_t seq, uint32_t time_window,
                               uint8_t out[COOKIE_LEN]) const {
    write_cookie(compute(secret_, sender, epoch, seq, time_window), out);
}

bool CookieChallenge::verify(uint8_t sender, uint16_t epoch, uint32_t seq, uint32_t now_ms,
                             const uint8_t candidate[COOKIE_LEN]) const {
    uint32_t window = time_window_for(now_ms);

    uint8_t expected[COOKIE_LEN];
    write_cookie(compute(secret_, sender, epoch, seq, window), expected);
    if (constant_time_equal(expected, candidate, COOKIE_LEN)) return true;

    if (window > 0) {
        write_cookie(compute(secret_, sender, epoch, seq, window - 1), expected);
        if (constant_time_equal(expected, candidate, COOKIE_LEN)) return true;
    }

    return false;
}

} // namespace sentinel
