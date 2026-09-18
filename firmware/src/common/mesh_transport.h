#pragma once
// Shared ESP-NOW mesh transport for all 3 hardware boards (field_node,
// gateway, attacker). This fills in the `// TODO: mesh transport (ESP-NOW)`
// comments each main.cpp already has a slot for at its send call sites, and
// the `// TODO ... register on_mesh_packet() as the receive callback` in
// each setup().
//
// DESIGN: broadcast-only. Every board hears every other board's packets and
// filters by hdr.sender/hdr.type in its own on_mesh_packet() -- exactly
// what the existing code already does (gateway's node_name_for() switch,
// field_node's "CONTROL only accepted from NodeId::GATEWAY" check). This
// means no MAC-address pairing/pre-registration is needed: broadcast to
// FF:FF:FF:FF:FF:FF, let software filter by sender byte in the header.
// Simplest possible wiring for a fixed 3-4-board demo mesh where everyone
// already knows everyone's NodeId.
//
// NOT ENCRYPTED AT THIS LAYER. This only moves bytes between radios.
// AES-256-GCM (still TODO pending the handshake) goes on top, not instead.
//
// ESP-NOW needs WiFi radio initialized in station mode even though we
// never join an access point -- that's normal, not a bug.

#include <cstdint>
#include <cstddef>

namespace sentinel::mesh {

// Called once per received ESP-NOW frame, still fully serialized (15B
// header + payload, exactly what Fragmenter::split() produced on the other
// end). `rssi_dbm` is the received signal strength in dBm (typically
// -30 to -90; more negative = weaker). The caller deserializes the header
// with PacketHeader::deserialize() and hands off to its own
// on_mesh_packet().
using RecvCallback = void (*)(const uint8_t* data, size_t len, int rssi_dbm);

// Starts WiFi in station mode, initializes ESP-NOW, registers the
// broadcast peer, and wires `on_recv` as the receive handler. Call once
// from setup(), after Serial.begin(). Returns false (and logs why to
// Serial) if any step failed.
bool init(RecvCallback on_recv);

// Broadcasts one already-fragmented frame (<=250 bytes -- matches
// MAX_FRAGMENT_PAYLOAD's 235B payload + 15B header exactly) to every
// listening board. Returns false if ESP-NOW rejected the send (init()
// wasn't called, radio busy, or data too large).
bool broadcast(const uint8_t* data, size_t len);

} // namespace sentinel::mesh
