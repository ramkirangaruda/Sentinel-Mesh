// SentinelMesh attacker firmware — demo red-team node.
//
// Modes, selected over USB serial (so it can be driven from the console or
// a terminal during the demo), per the brief:
//   MODE REPLAY        capture the next packet seen, then replay it on repeat
//   MODE FLOOD          handshake flood (spam HELLOs) at field-1 -- the
//                        battery-powered node EnergyGate protects (brief v4
//                        "drain attack"). Sent as broadcast, so the gateway
//                        overhears it for its trace windows / FieldGuard.
//   MODE IMPERSONATE    spoof the field node's sender id with the attacker's
//                        own keys (should fail signature/HMAC verification
//                        on the gateway, which is the point — see brief
//                        threat model)
//   MODE WEAK_LINK      simulate a degraded link (drop/delay/jitter its own
//                        traffic) rather than attacking outright
//   MODE SLOW_DRIP      v4: ~1 handshake/min at field-1 -- stays under any
//                        fixed rate limit but still drains the battery over
//                        time (brief v4 section 6)
//   MODE OFF             stop whatever mode is running
//
// This only needs to construct and send plausible-looking packets; it does
// NOT need to hold valid keys for anything except IMPERSONATE, where using
// its OWN keys under the field node's claimed identity is exactly the
// attack (and exactly what the gateway's signature check should catch).
//
// STATUS: structural skeleton. Real packet transmission depends on the
// mesh transport (TODO, same as field_node/gateway) and on the packet
// capture buffer for REPLAY mode. Not yet build-verified on hardware.

#include <Arduino.h>
#include <vector>
#include "sentinel_proto/packet.h"
#include "sentinel_proto/fragment.h"
#include "common/board_config.h"
#include "common/mesh_transport.h"

using namespace sentinel;

enum class AttackMode { OFF, REPLAY, FLOOD, IMPERSONATE, WEAK_LINK, SLOW_DRIP };
static AttackMode g_mode = AttackMode::OFF;

// Captured packet for REPLAY mode.
static std::vector<uint8_t> g_captured_packet;
static bool g_have_capture = false;

static uint16_t g_flood_epoch_base = 0xA11C;  // 16-bit epoch (brief v2 6.1), bogus each time
static uint32_t g_flood_seq = 0;   // 32-bit seq per brief v2 section 7

// v4 (docs/v4_energy_split.md, firmware task 4): "the slow-drip profile
// (~1/min, brief section 6 -- 'sits under any fixed rate limit but still
// drains the cell')". A handshake attempt roughly once a minute never
// looks like a flood by rate alone -- the whole point is that a naive
// rate-limit defense passes it through, while EnergyGate's token bucket
// still bleeds down over the hour even at that low a rate. Reuses the
// FLOOD path's packet construction, just at a much slower cadence.
static uint16_t g_slow_drip_epoch_base = 0x5D91; // distinct base from FLOOD's, purely cosmetic
static uint32_t g_slow_drip_seq = 0;
constexpr uint32_t SLOW_DRIP_INTERVAL_MS = 60000; // ~1/min

// ---------------------------------------------------------------------
// Mode handlers — called from loop() at whatever cadence suits the mode.
// ---------------------------------------------------------------------

static void tick_replay() {
    if (!g_have_capture) {
        // Capture happens in mesh_recv_bridge() below, as soon as a real
        // packet from field-1 comes over the air -- nothing to do here
        // until that fires.
        return;
    }
    // Re-transmit the captured bytes verbatim, unmodified -- same sender,
    // same epoch/seq as when field-1 sent it. This should be rejected by
    // the gateway's replay window / freshness check (contract:
    // field/replay_rejected, or attack_detected with
    // details.kind = "replay_campaign" if sent in a burst).
    sentinel::mesh::broadcast(g_captured_packet.data(), g_captured_packet.size());
    delay(500);
}

static void tick_flood() {
    PacketHeader hdr;
    hdr.type = MsgType::HELLO;
    hdr.sender = static_cast<uint8_t>(NodeId::ATTACKER);
    hdr.epoch = g_flood_epoch_base++; // new bogus epoch each time
    hdr.seq = g_flood_seq++;
    hdr.time_ms = millis();
    hdr.frag_n = 1;

    uint8_t buf[HEADER_SIZE];
    hdr.serialize(buf, sizeof(buf));
    // Broadcast with no valid signature attached -- expected: field-1's
    // EnergyGate rules on every one (gate_decision events via the gateway,
    // "node": "field-1"), and the gateway's trace window crosses
    // classify_window()'s threshold -> attack_detected with
    // details.kind = "handshake_flood".
    sentinel::mesh::broadcast(buf, sizeof(buf));
    delay(50); // fast enough to trip hs_per_s thresholds, not so fast it starves the radio
}

static void tick_impersonate() {
    PacketHeader hdr;
    hdr.type = MsgType::HELLO;
    hdr.sender = static_cast<uint8_t>(NodeId::FIELD_1); // spoofed identity
    hdr.epoch = millis(); // plausible-looking, attacker doesn't know the real epoch
    hdr.seq = 0;
    hdr.time_ms = millis();
    hdr.frag_n = 1;

    uint8_t buf[HEADER_SIZE];
    hdr.serialize(buf, sizeof(buf));
    // TODO: sign with the ATTACKER's own ML-DSA/HMAC key (not field-1's —
    // that's the whole point) once the real handshake exists. Broadcasting
    // unsigned for now. Expected gateway behavior once signature
    // verification is wired up: it fails ->
    // handshake_rejected + attack_detected(details.kind="impersonation").
    sentinel::mesh::broadcast(buf, sizeof(buf));
    delay(1000);
}

static void tick_slow_drip() {
    static uint32_t last_ms = 0;
    uint32_t now = millis();
    if (now - last_ms < SLOW_DRIP_INTERVAL_MS) return;
    last_ms = now;

    PacketHeader hdr;
    hdr.type = MsgType::HELLO;
    hdr.sender = static_cast<uint8_t>(NodeId::ATTACKER);
    hdr.epoch = g_slow_drip_epoch_base++;
    hdr.seq = g_slow_drip_seq++;
    hdr.time_ms = now;
    hdr.frag_n = 1;

    uint8_t buf[HEADER_SIZE];
    hdr.serialize(buf, sizeof(buf));
    // At ~1/min this shouldn't trip classify_window()'s hs_per_s/hs_fail
    // FLOOD threshold (field_model.h) -- that's the point, per brief
    // section 6: a fixed rate limit lets it through (gate_policy.h's
    // RATELIMIT mode admits it), so it is where EnergyGate has to earn its
    // place. Expected: individually unremarkable gate_decision events from
    // field-1, while field-1's battery trends down over the run.
    sentinel::mesh::broadcast(buf, sizeof(buf));
}

static void tick_weak_link() {
    // Simulate a degraded link by sending the attacker's own traffic with
    // deliberately induced jitter/drops, rather than targeting anyone.
    // This exercises the gateway's `link_degraded` classification path
    // (rssi_var / loss_pct / jitter_ms thresholds in field_model.h)
    // without it being flagged as an attack.
    static uint32_t last = 0;
    uint32_t now = millis();
    uint32_t jitter = random(0, 400); // ms
    if (now - last >= 1000 + jitter) {
        // TODO: send a normal-looking DATA packet, occasionally dropped
        // (skip sending ~1 in 5) to simulate loss.
        last = now;
    }
}

// ---------------------------------------------------------------------
// Mesh receive (only used by REPLAY mode's capture-then-repeat)
// ---------------------------------------------------------------------

// Every other mode is send-only and ignores incoming traffic entirely.
// REPLAY mode uses this to grab the first real packet it overhears from
// field-1, verbatim, for tick_replay() to re-send later.
static void mesh_recv_bridge(const uint8_t* data, size_t len, int rssi_dbm) {
    (void)rssi_dbm;
    if (g_mode != AttackMode::REPLAY || g_have_capture) return;

    PacketHeader hdr;
    if (!PacketHeader::deserialize(data, len, hdr)) return;
    if (hdr.sender != static_cast<uint8_t>(NodeId::FIELD_1)) return;

    g_captured_packet.assign(data, data + len);
    g_have_capture = true;
    Serial.println("LOG replay: captured a real packet from field-1");
}

// ---------------------------------------------------------------------
// Serial command intake
// ---------------------------------------------------------------------

static void handle_command(const String& cmd) {
    if (cmd == "MODE REPLAY") {
        g_mode = AttackMode::REPLAY;
        g_have_capture = false;
    } else if (cmd == "MODE FLOOD") {
        g_mode = AttackMode::FLOOD;
    } else if (cmd == "MODE IMPERSONATE") {
        g_mode = AttackMode::IMPERSONATE;
    } else if (cmd == "MODE WEAK_LINK") {
        g_mode = AttackMode::WEAK_LINK;
    } else if (cmd == "MODE SLOW_DRIP") {
        g_mode = AttackMode::SLOW_DRIP;
    } else if (cmd == "MODE OFF") {
        g_mode = AttackMode::OFF;
    } else {
        Serial.print("LOG unknown command: ");
        Serial.println(cmd);
        return;
    }
    Serial.print("LOG mode set to ");
    Serial.println(cmd);
}

// ---------------------------------------------------------------------
// Arduino entry points
// ---------------------------------------------------------------------

void setup() {
    Serial.begin(board::CONSOLE_SERIAL_BAUD);
    randomSeed(esp_random());

    if (!sentinel::mesh::init(mesh_recv_bridge)) {
        Serial.println("LOG attacker: ESP-NOW init failed -- mesh traffic will not work");
    }

    Serial.println("LOG attacker boot complete. Commands: MODE REPLAY|FLOOD|IMPERSONATE|WEAK_LINK|SLOW_DRIP|OFF");
}

void loop() {
    while (Serial.available()) {
        String line = Serial.readStringUntil('\n');
        line.trim();
        if (line.length() > 0) handle_command(line);
    }

    switch (g_mode) {
        case AttackMode::REPLAY: tick_replay(); break;
        case AttackMode::FLOOD: tick_flood(); break;
        case AttackMode::IMPERSONATE: tick_impersonate(); break;
        case AttackMode::WEAK_LINK: tick_weak_link(); break;
        case AttackMode::SLOW_DRIP: tick_slow_drip(); break;
        case AttackMode::OFF: delay(100); break;
    }
}
