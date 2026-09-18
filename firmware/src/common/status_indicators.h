#pragma once
// Shared RGB LED + buzzer status helper for field_node and gateway (the 2
// boards that actually have these per the BOM — attacker doesn't link
// against the .cpp usage, just doesn't call it).
//
// Brief v2 section 10 / section 12 demo flow:
//   green         = secure (normal operation)
//   yellow        = degraded crypto mode or weak link (still secure)
//   steady red    = network attack detected
//   flashing red  = physical tamper (case opened / moved / voltage anomaly)
//
// ESP32-only (digitalWrite/tone) — not part of the host-side unit test
// suite.

#include <Arduino.h>
#include "common/board_config.h"

namespace sentinel {

enum class StatusColor { GREEN, YELLOW, STEADY_RED, FLASHING_RED, OFF };

inline void status_indicators_init() {
    pinMode(board::PIN_LED_R, OUTPUT);
    pinMode(board::PIN_LED_G, OUTPUT);
    pinMode(board::PIN_LED_B, OUTPUT);
    pinMode(board::PIN_BUZZER, OUTPUT);
}

// Call every loop() iteration (cheap) so FLASHING_RED can animate off
// `millis()` without its own timer state.
inline void set_status_color(StatusColor c) {
    bool r = false, g = false, b = false;
    switch (c) {
        // Using blue for "secure" instead of green -- the green LED on this
        // hardware is noticeably dimmer/harder to see than blue. GREEN is
        // still the enum/logical name used everywhere else in the code
        // (it just means "secure"), this only changes which physical color
        // represents it.
        case StatusColor::GREEN:        b = true; break;
        case StatusColor::YELLOW:       r = true; g = true; break;
        case StatusColor::STEADY_RED:   r = true; break;
        case StatusColor::FLASHING_RED: r = (millis() / 300) % 2 == 0; break;
        case StatusColor::OFF:          break;
    }
    digitalWrite(board::PIN_LED_R, r ? HIGH : LOW);
    digitalWrite(board::PIN_LED_G, g ? HIGH : LOW);
    digitalWrite(board::PIN_LED_B, b ? HIGH : LOW);
}

// Short buzzer chirp — call once when a state transitions into an alert,
// not every loop iteration (don't want a continuous tone drowning the demo).
inline void buzz_alert(uint16_t freq_hz = 2000, uint16_t duration_ms = 150) {
    tone(board::PIN_BUZZER, freq_hz, duration_ms);
}

} // namespace sentinel
