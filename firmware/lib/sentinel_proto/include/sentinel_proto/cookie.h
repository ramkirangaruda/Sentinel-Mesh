#pragma once
#include <cstdint>
#include <cstddef>

// Stateless DTLS-style return-routability cookie for the mesh handshake
// (brief v4 / docs/v4_energy_split.md, firmware task 2: "8-byte value
// derived from a secret + sender id + time; refuse to reassemble until
// it's echoed back."). Not a novel construction -- same idea DTLS and QUIC
// use to make a handshake-flood attacker prove it can receive traffic at
// the address it claims before the gateway commits any reassembly buffer
// or CPU time to a real HELLO.
//
// The gateway is stateless about this: it never stores an issued cookie.
// Instead, `verify()` recomputes what the cookie *should* be for
// (sender, epoch, seq, time_window) and compares. `time_window` is a
// coarse tick (millis() / COOKIE_WINDOW_MS) so a cookie is valid for a
// short sliding interval without the gateway remembering who it gave one
// to -- an attacker replaying an old cookie outside that window is
// rejected the same way a stale-timestamp packet is in replay.h.
//
// Bound to (epoch, seq) (paper's MODE FORGE + ECHO finding, 2026-10-27:
// the cookie used to depend only on (sender, time_window), so ANY HELLO
// from that sender inside the ~2-4 s window carried a valid cookie --
// including one with a freshly incremented (epoch, seq) the cookie was
// never issued for. An attacker that echoes one cookie back onto a cached,
// repeatedly-resent HELLO (changing only epoch/seq each resend) then had
// every resend admitted, at the cost of one cookie round trip per ~2-4 s.
// Binding the cookie to the exact (epoch, seq) it was challenged for closes
// this: a legitimate initiator retries a challenged HELLO with the SAME
// header (epoch, seq) it was challenged on (decisions.md #5 -- it resends
// the same signed HELLO, cookie field filled in, without resigning), so the
// bound cookie still verifies for that retry; an attacker that wants a
// different (epoch, seq) admitted now needs a fresh CHALLENGE for that
// exact (epoch, seq), i.e. one round trip per admitted HELLO, not per
// window.
//
// No Arduino.h dependency -- host-testable like the rest of sentinel_proto.
//
// Security note: this uses a portable integer mixing function (not a
// cryptographic MAC) so it stays host-testable without pulling in
// wolfCrypt/mbedtls here. That's fine for its actual job -- proving return
// routability against a spoofed-source flood, not confidentiality or
// forgery-resistance against someone who can already see gateway traffic.
// If that threat model changes, swap the mix in cookie.cpp for an
// HMAC-SHA256 (truncated to COOKIE_LEN) using auth_fallback.h's mbedtls
// dependency -- the generate()/verify() interface doesn't need to change.

namespace sentinel {

constexpr size_t COOKIE_LEN = 8;
constexpr uint32_t COOKIE_WINDOW_MS = 2000; // a cookie is valid for ~1-2 windows

class CookieChallenge {
public:
    // `secret` should be a per-boot random value (esp_random() on target);
    // fixed here only so host tests are deterministic.
    explicit CookieChallenge(uint32_t secret) : secret_(secret) {}

    // Derives the 8-byte cookie for (sender, epoch, seq, time_window) into `out`. `epoch`/`seq`
    // are the challenged HELLO's own header fields (PacketHeader), so the cookie only answers
    // for that exact HELLO, not for "this sender, right now".
    void generate(uint8_t sender, uint16_t epoch, uint32_t seq, uint32_t time_window,
                  uint8_t out[COOKIE_LEN]) const;

    // Recomputes the expected cookie for (sender, epoch, seq, now_ms) and accepts a match
    // against the current window OR the immediately preceding one, so a request arriving just
    // after a window boundary isn't spuriously rejected. Returns true iff `candidate` matches
    // either. `epoch`/`seq` must be the SAME HELLO's header fields that were challenged --
    // a cookie issued for one (epoch, seq) does not verify for another, even from the same
    // sender in the same window.
    bool verify(uint8_t sender, uint16_t epoch, uint32_t seq, uint32_t now_ms,
               const uint8_t candidate[COOKIE_LEN]) const;

    static uint32_t time_window_for(uint32_t now_ms) { return now_ms / COOKIE_WINDOW_MS; }

private:
    uint32_t secret_;
};

} // namespace sentinel
