#pragma once
#include <cstdint>
#include "sentinel_proto/energygate.h"

// Rolling 5-second link statistics for EnergyGate's features, kept as five
// 1-second buckets so the feature vector is always "the last ~5 s" and a flood
// is visible within a second, rather than only when a fixed window closes.
//
// Feature definitions follow trace.h's TraceWindowCounters (the definitions the
// model was fitted on) with these deliberate differences, recorded in
// paper/decisions.md:
//   * hs_per_s counts handshake ATTEMPTS (a HELLO's fragment 0), not fragments.
//   * loss_pct = frames lost at the receive queue / (received + lost). The
//     original definition (sequence gaps) was never populated on hardware.
//   * the window is shorter than 5 s for the first seconds after boot.
//
// No Arduino.h dependency -- host-testable.

namespace sentinel {

struct LinkCounters {
    uint32_t hs_count = 0;          // HELLO attempts (fragment 0 seen)
    uint32_t hs_fail = 0;           // HELLOs that failed verification
    uint32_t frag_started = 0;      // HELLO reassembly sets begun
    uint32_t frag_completed = 0;    // ... that completed
    uint32_t total_received = 0;    // frames that reached the protocol layer
    uint32_t duplicate_count = 0;   // replayed / duplicate frames rejected
    uint32_t lost = 0;              // frames dropped at the RX queue
    uint32_t rssi_samples = 0;
    double rssi_sum = 0;
    double rssi_sumsq = 0;
};

class SlidingLink {
public:
    static constexpr int BUCKETS = 5;
    static constexpr uint32_t BUCKET_MS = 1000;

    void reset(uint32_t now_ms);
    // Rotates buckets so that `now_ms` falls in the current one (call often).
    void advance(uint32_t now_ms);
    LinkCounters& cur() { return b_[idx_]; }
    LinkCounters total() const;
    void add_rssi(float dbm) {
        LinkCounters& c = cur();
        c.rssi_sum += dbm; c.rssi_sumsq += static_cast<double>(dbm) * dbm; c.rssi_samples++;
    }
    // Fills f[] in energygate.h's FEATURE_ORDER. battery_pct comes from the caller.
    void features(float f[ENERGYGATE_NUM_FEATURES], float battery_pct, uint32_t now_ms) const;

private:
    LinkCounters b_[BUCKETS];
    int idx_ = 0;
    uint32_t bucket_start_ms_ = 0;
    uint32_t started_ms_ = 0;
};

} // namespace sentinel
