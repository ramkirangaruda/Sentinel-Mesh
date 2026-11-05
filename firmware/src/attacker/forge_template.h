#pragma once
#include <cstdint>
#include <cstddef>
#include <cstring>

// Host-testable cache for MODE FORGE (paper/TASK_FORGE_ATTACKER.md). Holds ONE signed HELLO,
// built once by main.cpp's job_make_forge_template() via the real pqc::initiator_make_hello(),
// and resent verbatim with a fresh (epoch, seq) each tick -- a correctly ENCODED ML-DSA signature
// passes the cheap unpacking checks that reject FLOOD's random bytes, so field-1 runs the full
// verification (and fails only at the end, since the key and transcript don't match the claimed
// sender) every time this is resent. See the file header of main.cpp and
// paper/CONTEXT_2026-10-24.md "Finding 2".
//
// No crypto and no Arduino.h dependency here -- building the real signature is main.cpp's job
// (it needs pqc::initiator_make_hello and the crypto task); this just caches the resulting bytes
// and tracks readiness, so the invariants the task's tests ask for (built once, never mutated by
// a resend, cleared on MODE OFF) are host-testable without PQClean linked in.

namespace sentinel {

template <size_t N>
class CachedTemplate {
public:
    bool ready() const { return ready_; }

    // Copies in the signed bytes once. Returns false (and leaves state unready) if called while
    // already ready() -- job_make_forge_template() checks ready() before signing again, but this
    // guards a stray re-sign from clobbering the cached template mid-attack.
    bool set(const uint8_t* bytes, size_t len) {
        if (ready_ || len != N) return false;
        std::memcpy(buf_, bytes, N);
        ready_ = true;
        return true;
    }

    const uint8_t* data() const { return buf_; }
    // Mutable access for hello_set_cookie(): the cookie sits outside the signed transcript
    // (pqc_handshake.h), so patching it in place after set() does not invalidate the cached
    // signature -- this is the same property tick_insider/tick_adaptive rely on for ECHO.
    uint8_t* mutable_data() { return buf_; }
    size_t size() const { return N; }

    void clear() { ready_ = false; }

private:
    uint8_t buf_[N] = {};
    bool ready_ = false;
};

} // namespace sentinel
