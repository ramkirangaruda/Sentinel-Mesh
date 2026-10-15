#include "sentinel_proto/link_window.h"

namespace sentinel {

void SlidingLink::reset(uint32_t now_ms) {
    for (auto& c : b_) c = LinkCounters{};
    idx_ = 0;
    bucket_start_ms_ = now_ms;
    started_ms_ = now_ms;
}

void SlidingLink::advance(uint32_t now_ms) {
    uint32_t elapsed = now_ms - bucket_start_ms_;
    if (elapsed < BUCKET_MS) return;
    uint32_t steps = elapsed / BUCKET_MS;
    if (steps >= BUCKETS) {
        for (auto& c : b_) c = LinkCounters{};
        idx_ = 0;
    } else {
        for (uint32_t i = 0; i < steps; i++) {
            idx_ = (idx_ + 1) % BUCKETS;
            b_[idx_] = LinkCounters{};
        }
    }
    bucket_start_ms_ += steps * BUCKET_MS;
}

LinkCounters SlidingLink::total() const {
    LinkCounters t;
    for (const auto& c : b_) {
        t.hs_count += c.hs_count;
        t.hs_fail += c.hs_fail;
        t.frag_started += c.frag_started;
        t.frag_completed += c.frag_completed;
        t.total_received += c.total_received;
        t.duplicate_count += c.duplicate_count;
        t.lost += c.lost;
        t.rssi_samples += c.rssi_samples;
        t.rssi_sum += c.rssi_sum;
        t.rssi_sumsq += c.rssi_sumsq;
    }
    return t;
}

void SlidingLink::features(float f[ENERGYGATE_NUM_FEATURES], float battery_pct, uint32_t now_ms) const {
    LinkCounters t = total();
    // Window length: 5 s once the buffer is full; shorter (>= 1 s) just after boot.
    uint32_t span = (now_ms - started_ms_);
    uint32_t window_ms = span >= BUCKETS * BUCKET_MS ? BUCKETS * BUCKET_MS : (span < BUCKET_MS ? BUCKET_MS : span);

    f[EG_HS_PER_S] = 1000.0f * t.hs_count / static_cast<float>(window_ms);
    f[EG_HS_FAIL] = static_cast<float>(t.hs_fail);
    float mean = t.rssi_samples ? static_cast<float>(t.rssi_sum / t.rssi_samples) : 0.0f;
    f[EG_RSSI_MEAN] = mean;
    f[EG_RSSI_VAR] = t.rssi_samples < 2 ? 0.0f
                                         : static_cast<float>(t.rssi_sumsq / t.rssi_samples - static_cast<double>(mean) * mean);
    uint32_t denom = t.total_received + t.lost;
    f[EG_LOSS_PCT] = denom ? 100.0f * t.lost / denom : 0.0f;
    f[EG_DUP_PCT] = t.total_received ? 100.0f * t.duplicate_count / t.total_received : 0.0f;
    f[EG_FRAG_COMPLETE_PCT] = t.frag_started ? 100.0f * t.frag_completed / t.frag_started : 100.0f;
    f[EG_BATTERY_PCT] = battery_pct;
}

} // namespace sentinel
