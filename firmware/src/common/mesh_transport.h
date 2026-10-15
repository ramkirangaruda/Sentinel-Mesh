#pragma once
// ESP-NOW broadcast transport shared by field_node, gateway and attacker.
// Adapted from the teammate's branch (origin/v4-esp-now-and-handshake), with
// three changes needed for the paper's measurements:
//   * receive callback only queues the frame; all protocol work happens in the
//     caller's task (poll()), so a flood cannot run crypto inside the Wi-Fi task;
//   * real per-frame RSSI on Arduino-ESP32 2.x / IDF 4.4, where esp_now's
//     callback has none: a promiscuous-mode callback records the RSSI of ESP-NOW
//     (vendor action) frames by source MAC and the receive path looks it up.
//     If no sample exists the frame is flagged rssi_valid=false and carries -50;
//   * blocking send that waits for the driver's send callback, so a 20-fragment
//     message is paced instead of overflowing the ESP-NOW send queue.
//
// Broadcast only: every board hears every frame and filters on hdr.sender.
// NOT encrypted at this layer (AES-256-GCM goes on top, session.h).

#include <cstddef>
#include <cstdint>

namespace sentinel::mesh {

constexpr size_t MAX_FRAME = 250; // ESP-NOW v1 limit (= 15 B header + 235 B payload)

struct Frame {
    uint8_t data[MAX_FRAME];
    uint8_t len;
    int8_t rssi;       // dBm
    bool rssi_valid;   // false -> rssi is the -50 placeholder
    uint32_t rx_ms;    // millis() at receive
};

// Starts Wi-Fi (STA, fixed channel), ESP-NOW, the RX queue and the RSSI sniffer.
bool init();

// Non-blocking: pops one received frame. Returns false when the queue is empty.
bool poll(Frame& out);

// Broadcasts one frame (<= MAX_FRAME). Blocks (max ~25 ms) until the radio is done.
bool broadcast(const uint8_t* data, size_t len);

// Frames lost because the RX queue was full (counted into loss_pct upstream).
uint32_t rx_overflow_count();
// Frames for which the sniffer had no RSSI sample.
uint32_t rssi_missing_count();

} // namespace sentinel::mesh
