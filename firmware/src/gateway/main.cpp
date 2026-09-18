// SentinelMesh gateway firmware ("Node B" in brief v2's storyboard).
//
// Responsibilities (brief v2 section 4 "Alert / recovery" + contracts/CONTRACT.md):
//  - Bridge the mesh (field node, attacker-under-test) to the console over
//    USB serial: print "EVT <json>" / "TRC <json>" lines, accept
//    "LABEL <x>" lines from the console.
//  - Keep per-window detection counters, run them through classify_window()
//    every window and print a TRC line (a stand-in field model until
//    ml/export/field_model.h exists — see field_model.h).
//  - Lock out a sender after it's flagged as an attack.
//  - Drive the OLED / RGB LED / buzzer as a status indicator (brief v2
//    section 10: green=secure, yellow=degraded, steady red=attack,
//    flashing red=tamper).
//  - v4: relay for EnergyGate, which runs on field-1 (the battery-powered
//    node the INA219 measures -- brief v4 sections 1-4; this board is
//    USB-powered, so gating here protected nothing the rig measures). The
//    gateway forwards the console's `DEFENSE <mode>` line to field-1 as a
//    CONTROL message, and turns field-1's GATE_REPORT messages into the
//    console's gate_decision / budget_exhausted events ("node": "field-1").
//    It still overhears the attacker's HELLOs for its trace windows, and it
//    still owns the signed-handshake check (impersonation, demo beat 5).
//  - Real handshake (HMAC-PSK fallback, see common/handshake.h for why not
//    true PQC yet): the gateway is always the INITIATOR (mains-powered,
//    it's the one that wants a session with the battery-powered field
//    node). Sends HELLO, verifies the field node's RESPONSE, replies with
//    CONFIRM. A field node never sends HELLO in this design -- if one
//    ever arrives claiming field-1's identity, that's an impersonation
//    attempt by definition, verified and flagged accordingly. Once a
//    session exists, DATA/GATE_REPORT are AES-256-GCM decrypted
//    (common/aead.h) and the replay filter's freshness check runs against
//    the session's own shared clock instead of raw, unsynchronized uptime.

#include <Arduino.h>
#include <Wire.h>
#include <vector>
#include <LiquidCrystal_I2C.h>

#include "sentinel_proto/packet.h"
#include "sentinel_proto/fragment.h"
#include "sentinel_proto/replay.h"
#include "sentinel_proto/field_model.h"
#include "sentinel_proto/event.h"
#include "sentinel_proto/trace.h"
#include "sentinel_proto/gate_policy.h"
#include "sentinel_proto/gate_msgs.h"
#include "common/board_config.h"
#include "common/status_indicators.h"
#include "common/mesh_transport.h"
#include "common/handshake.h"
#include "common/aead.h"

using namespace sentinel;

// ---------------------------------------------------------------------
// State
// ---------------------------------------------------------------------

static LiquidCrystal_I2C g_lcd(board::LCD_I2C_ADDR, board::LCD_COLS, board::LCD_ROWS);
static bool g_lcd_ok = false;
static StatusColor g_status = StatusColor::GREEN;

static Reassembler g_reassembler;
static ReplayFilter g_replay;
static TraceWindowCounters g_window;
static uint32_t g_window_start_ms = 0;
static const uint32_t WINDOW_MS = 5000;

// v4: the defence mode the console selected (`DEFENSE <mode>`), relayed to
// field-1, which is where EnergyGate actually runs. Kept here only to relay
// it and show it on the OLED.
static DefenseMode g_defense = DefenseMode::NONE;
// Re-sent periodically as well as on change: field-1 may reboot or miss a
// packet, and a stale mode would silently invalidate an experiment row.
constexpr uint32_t CONTROL_RESEND_MS = 30000;
static uint32_t g_last_control_ms = 0;
static uint32_t g_ctrl_seq = 0;
static uint16_t g_ctrl_epoch = 0; // random per boot (setup()), see ControlSequencer

// Current LABEL from the console (set via `LABEL <x>` serial command),
// tags the TRC lines that follow it until changed again. "normal" until
// told otherwise.
static char g_current_label[16] = "normal";

// Simple per-sender lockout after an attack is flagged. Index by NodeId
// byte value (small, fixed set of nodes on this mesh).
static bool g_locked_out[256] = {false};

// ---------------------------------------------------------------------
// Handshake / session state (HMAC-PSK fallback -- see common/handshake.h).
// The gateway is always the INITIATOR toward field-1.
// ---------------------------------------------------------------------

static bool g_session_established = false;
static uint8_t g_session_key[32] = {0};
static uint32_t g_gw_session_start_ms = 0; // this node's own millis() when the session began
static uint32_t g_gw_nonce_a = 0;
static bool g_have_pending_hello = false;
static uint32_t g_last_hello_attempt_ms = 0;
constexpr uint32_t HELLO_RETRY_MS = 4000; // resend HELLO if no RESPONSE arrives in time

// Maps field_model.h's short class name to the contract's details.kind
// vocabulary (contract: attack_detected details.kind is one of
// replay_campaign, handshake_flood, impersonation).
static const char* to_contract_attack_kind(int cls) {
    switch (static_cast<FieldClass>(cls)) {
        case FieldClass::REPLAY: return "replay_campaign";
        case FieldClass::FLOOD: return "handshake_flood";
        case FieldClass::IMPERSONATION: return "impersonation";
        default: return "unknown";
    }
}

// ---------------------------------------------------------------------
// EVT helpers
// ---------------------------------------------------------------------

// `details_kind`, when non-null, is written to details.kind. Required by
// contracts/event.schema.json for every attack_detected event (one of
// replay_campaign|handshake_flood|impersonation) -- without it the console
// rejects the POST with a 422.
static void emit_event(const char* layer, const char* type, const char* severity,
                        const char* node, const char* technique, const char* summary,
                        const char* reason1 = nullptr, const char* reason2 = nullptr,
                        const char* reason3 = nullptr, const char* details_kind = nullptr) {
    JsonDocument evt = new_event(layer, type, severity, node, technique, summary);
    if (reason1) evt["reasons"].add(reason1);
    if (reason2) evt["reasons"].add(reason2);
    if (reason3) evt["reasons"].add(reason3);
    if (details_kind) evt["details"]["kind"] = details_kind;
    Serial.println(to_evt_line(evt));
}

static const char* node_name_for(uint8_t sender) {
    switch (static_cast<NodeId>(sender)) {
        case NodeId::FIELD_1: return "field-1";
        case NodeId::GATEWAY: return "gateway";
        case NodeId::ATTACKER: return "attacker";
    }
    return "unknown";
}

// v4: gate_decision, on field-1's behalf. `score` is the model's probability
// the sender is real -- contract-required at the Event's top level, not in
// details. details.sender is the node whose HELLO was ruled on; budget_j /
// budget_max_j are the optional fields GET /status reads.
static void emit_gate_decision(const GateReport& r) {
    char summary[80];
    snprintf(summary, sizeof(summary), "EnergyGate %s for %s (defence: %s)",
             gate_action_name(r.action), node_name_for(r.sender), defense_mode_name(r.mode));
    JsonDocument evt = new_event("field", "gate_decision", gate_action_severity(r.action),
                                  "field-1", nullptr, summary);
    evt["score"] = r.prob_real;
    evt["details"]["action"] = gate_action_name(r.action);
    evt["details"]["sender"] = node_name_for(r.sender);
    evt["details"]["budget_j"] = r.budget_j;
    evt["details"]["budget_max_j"] = r.budget_max_j;
    Serial.println(to_evt_line(evt));
}

// v4: energy_alert when observed draw spikes over baseline. Severity
// scales with how far over baseline the draw is (contract: "low..critical,
// scales with draw multiple") -- once the Monitor board's INA219 readings
// actually reach the gateway (no data path yet, see src/monitor), call
// this from wherever that telemetry is consumed.
static const char* energy_alert_severity(float draw_mw, float baseline_mw) {
    if (baseline_mw <= 0.0f) return "low";
    float ratio = draw_mw / baseline_mw;
    if (ratio >= 5.0f) return "critical";
    if (ratio >= 3.0f) return "high";
    if (ratio >= 1.5f) return "medium";
    return "low";
}

static void emit_energy_alert(const char* node, float draw_mw, float baseline_mw, const char* summary) {
    JsonDocument evt = new_event("field", "energy_alert", energy_alert_severity(draw_mw, baseline_mw),
                                  node, nullptr, summary);
    evt["details"]["draw_mw"] = draw_mw;
    evt["details"]["baseline_mw"] = baseline_mw;
    Serial.println(to_evt_line(evt));
}

static void emit_budget_exhausted(const char* node, const char* summary) {
    emit_event("field", "budget_exhausted", "high", node, nullptr, summary);
}

static void lockout_sender(uint8_t sender, const char* node_name, const char* attack_kind) {
    g_locked_out[sender] = true;
    g_replay.reset(sender); // force re-handshake if they ever come back
    g_status = StatusColor::STEADY_RED;
    buzz_alert();
    emit_event("field", "attack_detected", "high", node_name, nullptr,
               "Sender locked out after attack", attack_kind, nullptr, nullptr, attack_kind);
}

// ---------------------------------------------------------------------
// Detection window -> TRC line + rule-based (or ML-exported) classification
// ---------------------------------------------------------------------

static void close_detection_window(uint32_t now_ms) {
    g_window.window_ms = now_ms - g_window_start_ms;

    JsonDocument trc = new_trace("gateway", g_current_label, now_ms, g_window);
    Serial.println(to_trc_line(trc));

    // Feed the same counters into classify_window() so the gateway can act
    // on detections live, independent of what the console does with the
    // recorded TRC line. Order must match field_model.h's documented
    // feature order.
    float features[FIELD_MODEL_NUM_FEATURES] = {
        g_window.hs_per_s(),
        static_cast<float>(g_window.hs_fail),
        static_cast<float>(g_window.replay_rej),
        static_cast<float>(g_window.auth_fail),
        static_cast<float>(g_window.stale),
        static_cast<float>(g_window.frag_timeout),
        g_window.rssi_mean(),
        g_window.rssi_var(),
        g_window.loss_pct(),
        g_window.jitter_mean_ms(),
    };
    int cls = classify_window(features);
    if (cls != static_cast<int>(FieldClass::NORMAL) &&
        cls != static_cast<int>(FieldClass::WEAK_LINK)) {
        const char* kind = to_contract_attack_kind(cls); // replay_campaign | handshake_flood | impersonation
        g_status = StatusColor::STEADY_RED;
        buzz_alert();
        String summary = String("Detection window classified as ") + kind;
        emit_event("field", "attack_detected", "high", "gateway", nullptr,
                   summary.c_str(), kind, nullptr, nullptr, kind);
        // TODO: once this is wired to the real sender identity (not just
        // "gateway"), call lockout_sender() here too — currently only the
        // per-packet replay_rejected path below has a concrete sender id
        // to lock out.
    } else if (cls == static_cast<int>(FieldClass::WEAK_LINK)) {
        if (g_status != StatusColor::STEADY_RED && g_status != StatusColor::FLASHING_RED) {
            g_status = StatusColor::YELLOW;
        }
        emit_event("field", "link_degraded", "low", "field-1", nullptr,
                    "Link quality degraded this window");
    } else if (g_status != StatusColor::STEADY_RED && g_status != StatusColor::FLASHING_RED) {
        g_status = StatusColor::GREEN;
    }


    g_window.reset();
    g_window.window_ms = WINDOW_MS;
    g_window_start_ms = now_ms;
}

// ---------------------------------------------------------------------
// Handshake send helpers (initiator side)
// ---------------------------------------------------------------------

static void send_handshake_msg(MsgType type, const uint8_t* payload, size_t len, uint32_t now_ms) {
    PacketHeader hdr;
    hdr.type = type;
    hdr.sender = static_cast<uint8_t>(NodeId::GATEWAY);
    hdr.epoch = g_ctrl_epoch; // reuse the same per-boot random epoch CONTROL already uses
    hdr.seq = g_ctrl_seq++;
    hdr.time_ms = now_ms;
    auto frags = Fragmenter::split(hdr, payload, len);
    for (auto& frag : frags) {
        sentinel::mesh::broadcast(frag.data(), frag.size());
    }
}

// Sends (or re-sends) HELLO if no session exists yet. Called every loop().
static void maybe_initiate_handshake(uint32_t now_ms) {
    if (g_session_established) return;
    if (now_ms - g_last_hello_attempt_ms < HELLO_RETRY_MS) return;
    g_last_hello_attempt_ms = now_ms;

    g_gw_nonce_a = esp_random();
    g_have_pending_hello = true;
    uint8_t hello[handshake::HELLO_LEN];
    handshake::build_hello(static_cast<uint8_t>(NodeId::GATEWAY), g_gw_nonce_a, hello);
    send_handshake_msg(MsgType::HELLO, hello, sizeof(hello), now_ms);
    Serial.println("LOG handshake: sent HELLO to field-1");
}

// ---------------------------------------------------------------------
// Serial line handling: console -> gateway (LABEL), gateway -> console (EVT/TRC/LOG)
// ---------------------------------------------------------------------

// Relays the current defence mode to field-1 as a CONTROL message.
static void send_control_to_field_node(uint32_t now_ms) {
    ControlMsg m;
    m.kind = ControlKind::DEFENSE;
    m.value = static_cast<uint8_t>(g_defense);
    uint8_t payload[CONTROL_LEN];
    serialize_control(m, payload, sizeof(payload));
    send_handshake_msg(MsgType::CONTROL, payload, sizeof(payload), now_ms);
    g_last_control_ms = now_ms;
}

static void handle_console_line(const String& line) {
    if (line.startsWith("LABEL ")) {
        String label = line.substring(6);
        label.trim();
        label.toCharArray(g_current_label, sizeof(g_current_label));
        Serial.print("LOG label set to ");
        Serial.println(g_current_label);
    } else if (line.startsWith("DEFENSE ")) {
        // contracts/CONTRACT.md: `DEFENSE <none|ratelimit|cookie|gate>`. The
        // gateway does not act on it -- field-1 runs EnergyGate -- it relays it.
        String mode = line.substring(8);
        mode.trim();
        DefenseMode parsed;
        if (parse_defense_mode(mode.c_str(), parsed)) {
            g_defense = parsed;
            send_control_to_field_node(millis());
            Serial.printf("LOG defence mode %s relayed to field-1\n", defense_mode_name(g_defense));
        } else {
            Serial.print("LOG unknown defence mode: ");
            Serial.println(mode);
        }
    }
    // Anything else (e.g. the attacker's MODE lines) is ignored: the console
    // sends every control line to every board, and each acts on its own.
}

// v4: one EnergyGate decision from field-1 -> the console's events.
static void on_gate_report(const uint8_t* payload, size_t payload_len) {
    GateReport r;
    if (!deserialize_gate_report(payload, payload_len, r)) {
        Serial.println("LOG malformed GATE_REPORT from field-1 dropped");
        return;
    }
    emit_gate_decision(r);
    if (r.budget_exhausted_edge) {
        emit_budget_exhausted("field-1",
                              "EnergyGate budget exhausted on field-1 -- dropping admissions until it refills");
    }
}

// ---------------------------------------------------------------------
// Mesh packet handling
// ---------------------------------------------------------------------

// Called once per received, header-parsed packet from the mesh transport.
static void on_mesh_packet(const PacketHeader& hdr, const uint8_t* payload, size_t payload_len,
                            float rssi, uint32_t now_ms) {
    g_window.add_rssi(rssi);

    if (g_locked_out[hdr.sender]) {
        return; // silently drop, sender is locked out
    }

    // RESPONSE finalizes the handshake this node initiated (HELLO above).
    // Small, single-fragment, handled directly -- no reassembly/replay
    // infra needed for a 40-byte message, and there's no session clock to
    // freshness-check it against yet anyway.
    if (hdr.type == MsgType::RESPONSE && hdr.sender == static_cast<uint8_t>(NodeId::FIELD_1)) {
        uint32_t nonce_b;
        if (g_have_pending_hello &&
            handshake::verify_response(hdr.sender, g_gw_nonce_a, payload, payload_len, nonce_b)) {
            handshake::derive_session_key(g_gw_nonce_a, nonce_b, g_session_key);
            g_session_established = true;
            g_gw_session_start_ms = millis();
            g_have_pending_hello = false;

            uint8_t confirm[handshake::CONFIRM_LEN];
            handshake::build_confirm(static_cast<uint8_t>(NodeId::GATEWAY), g_gw_nonce_a, nonce_b, confirm);
            send_handshake_msg(MsgType::CONFIRM, confirm, sizeof(confirm), now_ms);
            Serial.println("LOG handshake: session established with field-1, sent CONFIRM");
        } else {
            Serial.println("LOG handshake: RESPONSE verify failed or unexpected (no pending HELLO)");
        }
        return;
    }

    const char* node_name = (hdr.sender == static_cast<uint8_t>(NodeId::FIELD_1)) ? "field-1" : "attacker";

    if (hdr.type == MsgType::HELLO) {
        g_window.hs_count++;
        if (hdr.frag_i == 0) g_window.frag_sets_started++;

        if (hdr.sender == static_cast<uint8_t>(NodeId::FIELD_1)) {
            // The field node never sends HELLO in this handshake design
            // (the gateway is always the initiator) -- any HELLO claiming
            // this identity is an impersonation attempt, not a protocol
            // bug. Verify it: it can only ever pass if whoever sent it
            // actually holds the shared PSK.
            uint32_t nonce_a;
            if (!handshake::verify_hello(hdr.sender, payload, payload_len, nonce_a)) {
                g_window.hs_fail++;
                g_window.auth_fail++;
                emit_event("field", "handshake_rejected", "high", "field-1", "T0830",
                           "HELLO claiming field-1's identity failed the HMAC-PSK check",
                           nullptr, nullptr, nullptr, nullptr);
            }
        }
        // A HELLO from the attacker's own identity (FLOOD mode) isn't a
        // signature check at all -- it's counted above for the trace
        // window / classify_window()'s FLOOD threshold, same as before.
    }

    // Replay/freshness check uses the session's own shared clock once a
    // handshake has completed; before that (or for anyone outside the
    // session, like the attacker) it falls back to raw uptime, which will
    // reliably read "stale" -- expected, not a bug, until a session exists.
    uint32_t effective_now_ms = g_session_established ? (millis() - g_gw_session_start_ms) : now_ms;

    g_window.total_received++;
    ReplayFilter::Result rr = g_replay.check(hdr.sender, hdr.seq, hdr.time_ms, effective_now_ms);
    switch (rr) {
        case ReplayFilter::Result::REPLAY_REJECTED:
            g_window.replay_rej++;
            emit_event("field", "replay_rejected", "medium",
                       node_name, "T1692.002", "Replayed packet rejected",
                       "seq behind replay window");
            return;
        case ReplayFilter::Result::STALE_TIMESTAMP:
            g_window.stale++;
            return;
        case ReplayFilter::Result::DUPLICATE:
            // Benign retry: drop silently, re-ACK (ACK send path is a TODO
            // pending the real transport). Brief v2 section 7: "If an
            // acknowledgement is lost, the sender retries with the same
            // sequence number. The receiver drops the copy and
            // re-acknowledges." Counted for v4's dup_pct free signal.
            g_window.duplicate_count++;
            return;
        case ReplayFilter::Result::ACCEPT:
            break;
    }

    std::vector<uint8_t> reassembled;
    bool complete = g_reassembler.feed(hdr, payload, payload_len, now_ms, reassembled);
    if (!complete) return;
    g_window.frag_sets_completed++;
    g_window.packets_received++;

    // AES-256-GCM decrypt for DATA/GATE_REPORT once a session exists. A
    // failed decrypt (wrong key, tampered payload, or a packet that's
    // actually still plaintext from before the session formed) drops the
    // packet rather than guessing -- see aead.h's "reject on failure" rule.
    const uint8_t* body = reassembled.data();
    size_t body_len = reassembled.size();
    std::vector<uint8_t> plaintext;
    if (g_session_established && (hdr.type == MsgType::DATA || hdr.type == MsgType::GATE_REPORT)) {
        uint8_t nonce[aead::GCM_NONCE_LEN];
        aead::build_nonce(hdr.sender, hdr.epoch, hdr.seq, nonce);
        uint8_t hdr_bytes[HEADER_SIZE];
        hdr.serialize(hdr_bytes, sizeof(hdr_bytes));
        if (!aead::decrypt(g_session_key, nonce, hdr_bytes, HEADER_SIZE,
                            reassembled.data(), reassembled.size(), plaintext)) {
            Serial.println("LOG decrypt failed -- dropping packet (wrong key, tampered, or pre-session plaintext)");
            return;
        }
        body = plaintext.data();
        body_len = plaintext.size();
    }

    // v4: field-1's EnergyGate decisions.
    if (hdr.type == MsgType::GATE_REPORT) {
        if (hdr.sender == static_cast<uint8_t>(NodeId::FIELD_1)) {
            on_gate_report(body, body_len);
        }
        return;
    }

    // DATA: `body`/`body_len` is now the plaintext pressure reading (once a
    // session exists -- see the decrypt block above). Once the field node
    // reports its own battery_pct here too, wire it into trace.h's optional
    // v4 field (currently left unset).
    (void)body;
    (void)body_len;
}

// Bridges the ESP-NOW radio layer (raw bytes + RSSI) to on_mesh_packet()'s
// (header, payload, rssi, now_ms) shape. Registered with
// sentinel::mesh::init() in setup().
static void mesh_recv_bridge(const uint8_t* data, size_t len, int rssi_dbm) {
    PacketHeader hdr;
    if (!PacketHeader::deserialize(data, len, hdr)) return;
    const uint8_t* payload = data + HEADER_SIZE;
    size_t payload_len = len - HEADER_SIZE;
    on_mesh_packet(hdr, payload, payload_len, static_cast<float>(rssi_dbm), millis());
}

// ---------------------------------------------------------------------
// Status display (brief v2 section 12 demo flow text)
// ---------------------------------------------------------------------

// Condensed for a real 16x2 character LCD (the BOM's "OLED" turned out to
// be this instead, see board_config.h) -- the original 4-line pixel-OLED
// layout doesn't fit, so this keeps just the status word and the defence
// mode, the two most demo-relevant facts.
static void update_status_display() {
    if (!g_lcd_ok) return;
    const char* status_text =
        (g_status == StatusColor::FLASHING_RED) ? "TAMPER!" :
        (g_status == StatusColor::STEADY_RED)   ? "ATTACK!" :
        (g_status == StatusColor::YELLOW)       ? "Degraded" : "Secure";

    char raw1[24];
    snprintf(raw1, sizeof(raw1), "Gateway [%s]", g_current_label);
    char line1[board::LCD_COLS + 1];
    snprintf(line1, sizeof(line1), "%-16s", raw1);

    char raw2[24];
    snprintf(raw2, sizeof(raw2), "%s %s", status_text, g_session_established ? "S:ok" : "S:--");
    char line2[board::LCD_COLS + 1];
    snprintf(line2, sizeof(line2), "%-16s", raw2);

    g_lcd.setCursor(0, 0);
    g_lcd.print(line1);
    g_lcd.setCursor(0, 1);
    g_lcd.print(line2);
}

// ---------------------------------------------------------------------
// Arduino entry points
// ---------------------------------------------------------------------

void setup() {
    Serial.begin(board::CONSOLE_SERIAL_BAUD);
    status_indicators_init();

    Wire.begin(board::I2C_SDA, board::I2C_SCL);
    g_lcd.init();
    g_lcd.backlight();
    g_lcd_ok = true; // LiquidCrystal_I2C has no return-value begin() to check
    update_status_display();

    g_window.reset();
    g_window.window_ms = WINDOW_MS;
    g_window_start_ms = millis();
    g_ctrl_epoch = static_cast<uint16_t>(esp_random());

    Serial.println("LOG gateway boot complete");

    if (!sentinel::mesh::init(mesh_recv_bridge)) {
        Serial.println("LOG gateway: ESP-NOW init failed -- mesh traffic will not work");
    }

    // TODO: run the crypto work in its own FreeRTOS task with a large stack
    // (brief v2 section 8: "Run the crypto in its own FreeRTOS task with a
    // large stack"). TODO (v4): the monitor board reports draw to the
    // console directly (NRG lines on its own USB serial), so
    // emit_energy_alert() has no data path here yet.
}

void loop() {
    // Console -> gateway serial line intake.
    while (Serial.available()) {
        String line = Serial.readStringUntil('\n');
        line.trim();
        if (line.length() > 0) {
            handle_console_line(line);
        }
    }

    set_status_color(g_status);

    uint32_t now = millis();
    maybe_initiate_handshake(now);
    if (now - g_last_control_ms >= CONTROL_RESEND_MS) {
        send_control_to_field_node(now); // keep field-1's mode in sync
    }
    if (now - g_window_start_ms >= WINDOW_MS) {
        size_t evicted = g_reassembler.expire(now);
        g_window.frag_timeout += static_cast<uint32_t>(evicted);
        close_detection_window(now);
        update_status_display();
    }

    delay(10);
}
