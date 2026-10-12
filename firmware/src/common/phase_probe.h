#pragma once
// Phase hook for sentinel_pqc: times each costly operation (so CPU-time numbers
// exist even with no energy rig attached) and, in energy builds, raises the
// GPIO4 marker around ONE whole handshake computation so the Monitor board
// attributes energy to it.
#include <Arduino.h>
#include "common/board_config.h"
#include "sentinel_pqc/pqc_handshake.h"

namespace sentinel {

struct PhaseTimes {
    uint32_t us[6] = {0, 0, 0, 0, 0, 0};   // last run of each pqc::Phase, in microseconds
    uint32_t t0[6] = {0, 0, 0, 0, 0, 0};
};

inline void phase_probe_hook(pqc::Phase p, bool begin, void* user) {
    PhaseTimes* t = static_cast<PhaseTimes*>(user);
    int i = static_cast<int>(p);
    if (begin) t->t0[i] = micros();
    else t->us[i] = micros() - t->t0[i];
}

inline void marker_high() {
#ifdef SENTINEL_ENERGY_MARKERS
    digitalWrite(board::PIN_ENERGY_MARKER, HIGH);
#endif
}
inline void marker_low() {
#ifdef SENTINEL_ENERGY_MARKERS
    digitalWrite(board::PIN_ENERGY_MARKER, LOW);
#endif
}

} // namespace sentinel
