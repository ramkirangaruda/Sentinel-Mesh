#pragma once
#include <cstdint>

// Pacing logic for the ADAPTIVE attacker (paper task S5 / experiment E7). No Arduino.h dependency, so
// it is host-testable (test_attacker_pacer.cpp).
//
// The attacker knows EnergyGate's 8 features (ml/sentinel_ml/energygate.py FEATURE_ORDER) and the
// rolling window field-1 computes them over (sentinel_proto/link_window.h: five 1 s buckets). Of the
// 8 features the attacker controls three directly:
//   hs_per_s  = HELLO attempts (fragment 0) in the window / window seconds. It counts EVERY sender's
//               HELLOs, so the legitimate gateway's share must be left room for.
//   hs_fail   = HELLOs that were admitted and then failed verification (0 for a validly signed
//               HELLO from an enrolled key, > 0 for forged ones).
//   dup_pct   = replayed / duplicate frames: 0 as long as every HELLO carries a fresh sequence number.
// It does not control rssi_*, loss_pct (the victim's receive queue) or frag_complete_pct (admitted sets
// complete when nothing is lost), and battery_pct is fixed at 100 on the rig (SIMULATED).
//
// Operating point against the shipped (SIMULATED-trained) tree in sentinel_proto/energygate_model.h:
// with hs_fail <= 1 and dup_pct <= 6 the score is 0.958 whenever hs_per_s <= 1.3956 (above it, 0.095),
// and a SPEND needs score >= 0.7 (gate_policy.h). 1.3956/s over a 5 s window is 6 HELLOs, so the default
// cap of 5 leaves one slot for the real gateway. These numbers describe THIS model; if EnergyGate is
// retrained (task S7) re-derive them or set PacerConfig from the new tree.
//
// Feedback: the attacker hears field-1's CHALLENGE (broadcast). A CHALLENGE means the score fell below
// the spend threshold (or, for a COOKIE/other defence, that the defence is not the gate), so the pacer
// backs off multiplicatively and then probes back up additively (AIMD), staying under the hard cap.

namespace sentinel {

struct PacerConfig {
    uint32_t window_ms = 5000;        // F's feature window (5 buckets x 1 s)
    uint32_t max_in_window = 5;       // hard cap on own HELLOs per window (model: <= 6 keeps hs_per_s <= 1.2)
    float max_rate_hz = 1.0f;         // never faster than this on average (<= max_in_window / window)
    float min_rate_hz = 0.05f;        // one per 20 s: the floor after repeated challenges
    float start_rate_hz = 0.5f;       // first guess
    float decrease = 0.5f;            // multiplicative back-off on a CHALLENGE
    float increase_hz = 0.1f;         // additive probe after quiet_ms without a CHALLENGE
    uint32_t quiet_ms = 10000;        // quiet period before probing upward
    uint32_t hold_ms = 5000;          // after a CHALLENGE, do not send for this long (lets the window drain)
    // Forged (spoofed-identity) mode: every admitted HELLO fails verification, so each send may become an
    // hs_fail. The tree needs hs_fail <= 1 in the window; cap the sends in the window at this value.
    // 0 = not forging (valid signatures, hs_fail stays 0).
    uint32_t max_fail_in_window = 0;
};

class AdaptivePacer {
public:
    explicit AdaptivePacer(const PacerConfig& cfg = PacerConfig()) { configure(cfg); }

    void configure(const PacerConfig& cfg) {
        cfg_ = cfg;
        if (cfg_.max_rate_hz * cfg_.window_ms / 1000.0f > cfg_.max_in_window)
            cfg_.max_rate_hz = static_cast<float>(cfg_.max_in_window) * 1000.0f / cfg_.window_ms;
        if (cfg_.min_rate_hz > cfg_.max_rate_hz) cfg_.min_rate_hz = cfg_.max_rate_hz;
        reset(0);
    }

    void reset(uint32_t now_ms) {
        rate_hz_ = clamp(cfg_.start_rate_hz);
        n_ = 0;
        last_send_ms_ = 0;
        any_sent_ = false;
        last_challenge_ms_ = 0;
        any_challenge_ = false;
        last_probe_ms_ = now_ms;
        hold_until_ms_ = 0;
        challenges_ = 0;
        sent_ = 0;
        (void)now_ms;
    }

    // True if a HELLO may be sent now.
    bool may_send(uint32_t now_ms) {
        step(now_ms);
        if (now_ms < hold_until_ms_) return false;
        expire(now_ms);
        if (n_ >= cfg_.max_in_window) return false;
        if (cfg_.max_fail_in_window > 0 && n_ >= cfg_.max_fail_in_window) return false;
        if (any_sent_) {
            uint32_t gap = static_cast<uint32_t>(1000.0f / rate_hz_);
            if (now_ms - last_send_ms_ < gap) return false;
        }
        return true;
    }

    // Call when a HELLO (fragment 0 reaches the air) is sent. An echoed cookie resend counts as well:
    // field-1 counts its fragment 0 as another attempt.
    void on_sent(uint32_t now_ms) {
        expire(now_ms);
        if (n_ < kMaxTrack) sent_at_[n_++] = now_ms;
        last_send_ms_ = now_ms;
        any_sent_ = true;
        sent_++;
    }

    // Field-1 answered with a CHALLENGE: detected. Back off and hold.
    void on_challenge(uint32_t now_ms) {
        challenges_++;
        any_challenge_ = true;
        last_challenge_ms_ = now_ms;
        last_probe_ms_ = now_ms;
        rate_hz_ = clamp(rate_hz_ * cfg_.decrease);
        hold_until_ms_ = now_ms + cfg_.hold_ms;
    }

    float rate_hz() const { return rate_hz_; }
    uint32_t challenges() const { return challenges_; }
    uint32_t sent() const { return sent_; }
    uint32_t in_window(uint32_t now_ms) { expire(now_ms); return n_; }
    const PacerConfig& config() const { return cfg_; }

private:
    static constexpr uint32_t kMaxTrack = 32;

    float clamp(float r) const {
        if (r < cfg_.min_rate_hz) return cfg_.min_rate_hz;
        if (r > cfg_.max_rate_hz) return cfg_.max_rate_hz;
        return r;
    }

    // Additive increase: one step per quiet_ms with no CHALLENGE since the last step or challenge.
    void step(uint32_t now_ms) {
        uint32_t since = now_ms - last_probe_ms_;
        if (since >= cfg_.quiet_ms && (!any_challenge_ || now_ms - last_challenge_ms_ >= cfg_.quiet_ms)) {
            rate_hz_ = clamp(rate_hz_ + cfg_.increase_hz);
            last_probe_ms_ = now_ms;
        }
    }

    void expire(uint32_t now_ms) {
        uint32_t k = 0;
        for (uint32_t i = 0; i < n_; i++)
            if (now_ms - sent_at_[i] < cfg_.window_ms) sent_at_[k++] = sent_at_[i];
        n_ = k;
    }

    PacerConfig cfg_;
    float rate_hz_ = 0.5f;
    uint32_t sent_at_[kMaxTrack] = {};
    uint32_t n_ = 0;
    uint32_t last_send_ms_ = 0;
    bool any_sent_ = false;
    uint32_t last_challenge_ms_ = 0;
    bool any_challenge_ = false;
    uint32_t last_probe_ms_ = 0;
    uint32_t hold_until_ms_ = 0;
    uint32_t challenges_ = 0;
    uint32_t sent_ = 0;
};

} // namespace sentinel
