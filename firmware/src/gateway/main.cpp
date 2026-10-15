// SentinelMesh gateway firmware ("Node B" in brief v2's storyboard).
//
// Phase 6 (paper branch): real ESP-NOW transport and the real post-quantum
// handshake, with the gateway as INITIATOR.
//
// Responsibilities:
//  - Bridge the mesh to the console over USB serial: print "EVT <json>" /
//    "TRC <json>" lines, accept "LABEL <x>" / "DEFENSE <mode>" lines
//    (contracts/CONTRACT.md).
//  - Initiate and periodically refresh the handshake with field-1: signed
//    ML-KEM HELLO, verify the RESPONSE, send CONFIRM (lib/sentinel_pqc). Answer a
//    CHALLENGE from EnergyGate by echoing its cookie. Every attempt is logged
//    ("LOG hs ...") with its outcome and timings -- that is the legitimate
//    client's side of the experiment (legit connect %, extra delay).
//  - Receive field-1's AES-256-GCM DATA (which carries EnergyGate's exact
//    decision counters) and its plain GATE_REPORTs (-> console gate_decision).
//  - Relay the console's `DEFENSE <mode>` to field-1 as a CONTROL message.
//  - Keep per-window detection counters, classify them (field_model.h) and
//    print a TRC line per window. It overhears everyone's HELLOs for this.
//  - Notice impersonation for free: this board is the only legitimate sender of
//    frames carrying the gateway's id and never hears its own transmissions, so
//    any such frame it receives is forged.
//  - OLED / RGB LED / buzzer status (not in measurement builds).
//
// EnergyGate itself runs on field-1, not here (see CLAUDE.md).

#include <Arduino.h>
#include <Wire.h>
#include <vector>
#include <cstring>
#include <esp_system.h>
#include <esp_heap_caps.h>

#ifndef SENTINEL_MEASUREMENT_BUILD
#define SM_PERIPHERALS 1
#include <Adafruit_GFX.h>
#include <Adafruit_SSD1306.h>
#else
#define SM_PERIPHERALS 0
#endif

#include "sentinel_proto/packet.h"
#include "sentinel_proto/fragment.h"
#include "sentinel_proto/replay.h"
#include "sentinel_proto/field_model.h"
#include "sentinel_proto/event.h"
#include "sentinel_proto/trace.h"
#include "sentinel_proto/gate_policy.h"
#include "sentinel_proto/gate_msgs.h"
#include "sentinel_pqc/pqc_handshake.h"
#include "common/board_config.h"
#include "common/status_indicators.h"
#include "common/mesh_transport.h"
#include "common/msg_io.h"
#include "common/crypto_task.h"
#include "common/phase_probe.h"
#include "common/demo_keys.h"

using namespace sentinel;

#ifndef PQC_TASK_STACK_BYTES
#  if SENTINEL_PQC_LEVEL == 1
#    define PQC_TASK_STACK_BYTES 49152
#  else
#    define PQC_TASK_STACK_BYTES 90112
#  endif
#endif
// How often the gateway opens a fresh session. Energy experiments override this
// (e.g. -DREHANDSHAKE_PERIOD_MS=20000) so there are many handshakes per run.
#ifndef REHANDSHAKE_PERIOD_MS
#define REHANDSHAKE_PERIOD_MS 30000
#endif
#ifndef HS_TIMEOUT_MS
#define HS_TIMEOUT_MS 2500
#endif
#ifndef HS_BACKOFF_MAX_MS
#define HS_BACKOFF_MAX_MS 15000
#endif

// NIST level -> the ML-KEM number the contract's `rekey` event expects.
#if SENTINEL_PQC_LEVEL == 1
constexpr int kContractLevel = 512;
#else
constexpr int kContractLevel = 768;
#endif

// ---------------------------------------------------------------------
// State
// ---------------------------------------------------------------------

#if SM_PERIPHERALS
static Adafruit_SSD1306 g_oled(board::OLED_WIDTH, board::OLED_HEIGHT, &Wire, -1);
static bool g_oled_ok = false;
#endif
static StatusColor g_status = StatusColor::GREEN;

static Reassembler g_reasm;
static TraceWindowCounters g_window;
static uint32_t g_window_start_ms = 0;
static const uint32_t WINDOW_MS = 5000;

static DefenseMode g_defense = DefenseMode::NONE;
constexpr uint32_t CONTROL_RESEND_MS = 30000;
static uint32_t g_last_control_ms = 0;
static uint32_t g_ctrl_seq = 0;
static uint16_t g_ctrl_epoch = 0;

static char g_current_label[16] = "normal";
static bool g_locked_out[256] = {false};
static uint32_t g_rx_overflow_seen = 0;

// --- initiator state ---
enum class HsState : uint8_t { IDLE, BUILDING, WAIT_RESPONSE, PROCESSING };
static volatile HsState g_hs_state = HsState::IDLE;
static pqc::InitiatorState g_init;
static uint8_t g_hello_tx[pqc::HELLO_LEN];
static uint8_t g_resp_rx[pqc::RESPONSE_LEN];
static size_t g_resp_rx_len = 0;
struct Attempt {
    uint16_t epoch; uint32_t seq; uint32_t t_start_ms; uint32_t deadline_ms;
    uint8_t tries; bool challenged; uint32_t t_resp_ms;
};
static Attempt g_att = {};
static volatile bool g_cookie_ready = false;
static uint8_t g_cookie[pqc::COOKIE_BYTES];
static uint16_t g_epoch_ctr = 0;
static uint32_t g_seq_ctr = 1;
static uint32_t g_next_hs_ms = 3000;     // first attempt shortly after boot
static uint32_t g_backoff_ms = 1000;
static uint32_t g_rehandshake_period_ms = REHANDSHAKE_PERIOD_MS;
static bool g_first_session = true;
static PhaseTimes g_phase;
static Session g_session;
static uint32_t g_hs_started = 0, g_hs_ok = 0, g_hs_failed = 0;

// Outcome of an attempt, produced by the crypto task, printed by the loop task
// (Serial from two tasks would interleave and corrupt the console's line parser).
struct HsResult {
    volatile bool ready; bool ok; const char* reason; uint8_t tries; bool challenged;
    uint32_t total_ms; uint32_t resp_ms; uint32_t phase_us[6]; uint16_t epoch;
};
static HsResult g_result = {};

// --- overheard-HELLO set tracking (for the trace window's fragment features) ---
struct SetTrack { bool used; uint8_t sender; uint16_t epoch; uint32_t seq; uint8_t n; uint32_t got; uint32_t last_ms; };
static SetTrack g_sets[8];

// ---------------------------------------------------------------------
// EVT helpers
// ---------------------------------------------------------------------

static const char* to_contract_attack_kind(int cls) {
    switch (static_cast<FieldClass>(cls)) {
        case FieldClass::REPLAY: return "replay_campaign";
        case FieldClass::FLOOD: return "handshake_flood";
        case FieldClass::IMPERSONATION: return "impersonation";
        default: return "unknown";
    }
}

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

static void emit_budget_exhausted(const char* node, const char* summary) {
    emit_event("field", "budget_exhausted", "high", node, nullptr, summary);
}

static void emit_rekey(const char* reason) {
    JsonDocument evt = new_event("field", "rekey", "info", "field-1", nullptr, "New post-quantum session established");
    evt["details"]["level"] = kContractLevel;     // contract: 512 / 768 / 1024
    evt["details"]["reason"] = reason;
    Serial.println(to_evt_line(evt));
}

[[maybe_unused]] static void lockout_sender(uint8_t sender, const char* node_name, const char* attack_kind) {
    g_locked_out[sender] = true;
    g_status = StatusColor::STEADY_RED;
    buzz_alert();
    emit_event("field", "attack_detected", "high", node_name, nullptr,
               "Sender locked out after attack", attack_kind, nullptr, nullptr, attack_kind);
}

// ---------------------------------------------------------------------
// Overheard HELLO fragment sets (for frag_sets_started / completed / timeout)
// ---------------------------------------------------------------------

static void track_hello_frag(const PacketHeader& h, uint32_t now_ms) {
    SetTrack* slot = nullptr;
    for (auto& t : g_sets)
        if (t.used && t.sender == h.sender && t.epoch == h.epoch && t.seq == h.seq) { slot = &t; break; }
    if (!slot) {
        for (auto& t : g_sets) if (!t.used) { slot = &t; break; }
        if (!slot) return;   // table full: this set is simply not tracked
        *slot = {true, h.sender, h.epoch, h.seq, h.frag_n, 0, now_ms};
        g_window.frag_sets_started++;
    }
    if (h.frag_i < 32) slot->got |= (1u << h.frag_i);
    slot->last_ms = now_ms;
    uint32_t full = (slot->n >= 32) ? 0xFFFFFFFFu : ((1u << slot->n) - 1u);
    if ((slot->got & full) == full) {
        g_window.frag_sets_completed++;
        slot->used = false;
    }
}

static void expire_hello_sets(uint32_t now_ms) {
    for (auto& t : g_sets) {
        if (t.used && now_ms - t.last_ms > 1500) {
            g_window.frag_timeout++;
            t.used = false;
        }
    }
}

// ---------------------------------------------------------------------
// Detection window -> TRC line + classification
// ---------------------------------------------------------------------

static void close_detection_window(uint32_t now_ms) {
    g_window.window_ms = now_ms - g_window_start_ms;

    // Loss as seen by this board: frames dropped at the RX queue.
    uint32_t ov = mesh::rx_overflow_count();
    uint32_t lost = ov - g_rx_overflow_seen;
    g_rx_overflow_seen = ov;
    g_window.packets_expected = g_window.packets_received + lost;

    JsonDocument trc = new_trace("gateway", g_current_label, now_ms, g_window);
    Serial.println(to_trc_line(trc));

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
        const char* kind = to_contract_attack_kind(cls);
        g_status = StatusColor::STEADY_RED;
        buzz_alert();
        String summary = String("Detection window classified as ") + kind;
        emit_event("field", "attack_detected", "high", "gateway", nullptr,
                   summary.c_str(), kind, nullptr, nullptr, kind);
    } else if (cls == static_cast<int>(FieldClass::WEAK_LINK)) {
        if (g_status != StatusColor::STEADY_RED && g_status != StatusColor::FLASHING_RED) g_status = StatusColor::YELLOW;
        emit_event("field", "link_degraded", "low", "field-1", nullptr, "Link quality degraded this window");
    } else if (g_status != StatusColor::STEADY_RED && g_status != StatusColor::FLASHING_RED) {
        g_status = StatusColor::GREEN;
    }

    g_window.reset();
    g_window.window_ms = WINDOW_MS;
    g_window_start_ms = now_ms;
}

// ---------------------------------------------------------------------
// Initiator: handshake driver
// ---------------------------------------------------------------------

static void schedule_next(uint32_t now_ms, bool success) {
    if (success) {
        g_backoff_ms = 1000;
        g_next_hs_ms = now_ms + g_rehandshake_period_ms;
    } else {
        g_next_hs_ms = now_ms + g_backoff_ms;
        g_backoff_ms = g_backoff_ms * 2 > HS_BACKOFF_MAX_MS ? HS_BACKOFF_MAX_MS : g_backoff_ms * 2;
    }
}

// Sends the current g_hello_tx under a fresh seq (the cookie, if any, is already in it).
static bool transmit_hello() {
    g_att.seq = g_seq_ctr++;
    PacketHeader h;
    h.type = MsgType::HELLO;
    h.sender = static_cast<uint8_t>(NodeId::GATEWAY);
    h.epoch = g_att.epoch;
    h.seq = g_att.seq;
    h.time_ms = millis();
    return send_message(h, g_hello_tx, sizeof(g_hello_tx)) > 0;
}

static void finish(bool ok, const char* reason) {
    g_result.ok = ok;
    g_result.reason = reason;
    g_result.tries = g_att.tries;
    g_result.challenged = g_att.challenged;
    g_result.total_ms = millis() - g_att.t_start_ms;
    g_result.resp_ms = g_att.t_resp_ms ? g_att.t_resp_ms - g_att.t_start_ms : 0;
    g_result.epoch = g_att.epoch;
    for (int i = 0; i < 6; i++) g_result.phase_us[i] = g_phase.us[i];
    g_result.ready = true;
}

// --- crypto task jobs ---

static void job_make_and_send_hello(void*) {
    pqc::Hooks hk{phase_probe_hook, &g_phase};
    pqc::Result r = pqc::initiator_make_hello(g_init, static_cast<uint8_t>(NodeId::GATEWAY),
                                              static_cast<uint8_t>(NodeId::FIELD_1),
                                              demo_keys::SIG_SK_GATEWAY, hk, g_hello_tx);
    if (r != pqc::Result::OK) {
        finish(false, "make_hello_failed");
        g_hs_state = HsState::IDLE;
        return;
    }
    g_att.deadline_ms = millis() + HS_TIMEOUT_MS;
    g_hs_state = HsState::WAIT_RESPONSE;   // before transmitting: a CHALLENGE can arrive mid-send
    g_att.tries = 1;
    transmit_hello();
}

static void job_handle_response(void*) {
    pqc::Hooks hk{phase_probe_hook, &g_phase};
    pqc::SessionKeys keys;
    uint8_t confirm[pqc::CONFIRM_LEN];
    pqc::Result r = pqc::initiator_handle_response(g_init, static_cast<uint8_t>(NodeId::GATEWAY),
                                                   static_cast<uint8_t>(NodeId::FIELD_1),
                                                   demo_keys::SIG_PK_FIELD1, g_resp_rx, g_resp_rx_len,
                                                   hk, keys, confirm);
    if (r != pqc::Result::OK) {
        finish(false, pqc::result_name(r));
        g_hs_state = HsState::IDLE;
        return;
    }
    // Install the session, then send CONFIRM (field-1 activates on receiving it).
    g_session.active = false;
    g_session.peer = static_cast<uint8_t>(NodeId::FIELD_1);
    g_session.epoch = g_att.epoch;
    memcpy(g_session.k_tx, keys.k_i2r, sizeof(g_session.k_tx));   // initiator -> responder
    memcpy(g_session.k_rx, keys.k_r2i, sizeof(g_session.k_rx));
    g_session.tx_seq = 0;
    g_session.start_ms = millis();
    g_session.replay.reset(g_session.peer);
    PacketHeader h;
    h.type = MsgType::CONFIRM;
    h.sender = static_cast<uint8_t>(NodeId::GATEWAY);
    h.epoch = g_att.epoch;
    h.seq = g_att.seq;
    h.time_ms = millis();
    send_message(h, confirm, sizeof(confirm));
    g_session.active = true;
    finish(true, "ok");
    g_hs_state = HsState::IDLE;
}

static void start_attempt(uint32_t now_ms) {
    if (crypto_task_busy()) return;
    g_att = {};
    g_att.epoch = ++g_epoch_ctr;
    g_att.t_start_ms = now_ms;
    g_att.deadline_ms = now_ms + HS_TIMEOUT_MS + 1500;   // covers the keygen+sign before WAIT_RESPONSE
    g_hs_state = HsState::BUILDING;
    g_hs_started++;
    if (!crypto_task_submit(job_make_and_send_hello, nullptr)) {
        g_hs_state = HsState::IDLE;
        g_hs_started--;
    }
}

static void drive_handshake(uint32_t now_ms) {
    // Consume a finished attempt FIRST: it sets the next start time, and the state machine
    // below must not see the stale one (it used to start a second handshake straight away).
    if (g_result.ready) {
        g_result.ready = false;
        uint32_t now = millis();
        if (g_result.ok) {
            g_hs_ok++;
            schedule_next(now, true);
            Serial.printf("LOG hs ok epoch=%u tries=%u challenged=%d total_ms=%lu to_response_ms=%lu keygen_us=%lu sign_us=%lu verify_us=%lu decaps_us=%lu\n",
                          g_result.epoch, g_result.tries, g_result.challenged, (unsigned long)g_result.total_ms,
                          (unsigned long)g_result.resp_ms,
                          (unsigned long)g_result.phase_us[(int)pqc::Phase::KEM_KEYGEN],
                          (unsigned long)g_result.phase_us[(int)pqc::Phase::SIG_SIGN],
                          (unsigned long)g_result.phase_us[(int)pqc::Phase::SIG_VERIFY],
                          (unsigned long)g_result.phase_us[(int)pqc::Phase::KEM_DECAPS]);
            emit_rekey(g_first_session ? "initial" : "scheduled");
            g_first_session = false;
        } else {
            g_hs_failed++;
            schedule_next(now, false);
            Serial.printf("LOG hs fail reason=%s epoch=%u tries=%u challenged=%d total_ms=%lu next_in_ms=%lu\n",
                          g_result.reason, g_result.epoch, g_result.tries, g_result.challenged,
                          (unsigned long)g_result.total_ms, (unsigned long)(g_next_hs_ms - now));
        }
    }

    switch (g_hs_state) {
        case HsState::IDLE:
            if (now_ms >= g_next_hs_ms) start_attempt(now_ms);
            break;
        case HsState::WAIT_RESPONSE:
            if (g_cookie_ready && !crypto_task_busy()) {
                // EnergyGate challenged us: echo the cookie in the same signed HELLO (cookie is
                // outside the signed transcript, so no second signature is needed).
                g_cookie_ready = false;
                pqc::hello_set_cookie(g_hello_tx, g_cookie);
                g_att.challenged = true;
                g_att.tries++;
                g_att.deadline_ms = now_ms + HS_TIMEOUT_MS;
                transmit_hello();
            } else if (now_ms > g_att.deadline_ms) {
                finish(false, "timeout");
                g_hs_state = HsState::IDLE;
            }
            break;
        case HsState::BUILDING:
        case HsState::PROCESSING:
            if (now_ms > g_att.deadline_ms + 4000) {   // safety net, should never trigger
                finish(false, "stuck");
                g_hs_state = HsState::IDLE;
            }
            break;
    }
}

// ---------------------------------------------------------------------
// Console serial lines
// ---------------------------------------------------------------------

static void send_control_to_field_node(uint32_t now_ms) {
    ControlMsg m;
    m.kind = ControlKind::DEFENSE;
    m.value = static_cast<uint8_t>(g_defense);
    uint8_t payload[CONTROL_LEN];
    serialize_control(m, payload, sizeof(payload));
    PacketHeader hdr;
    hdr.type = MsgType::CONTROL;
    hdr.sender = static_cast<uint8_t>(NodeId::GATEWAY);
    hdr.epoch = g_ctrl_epoch;
    hdr.seq = g_ctrl_seq++;
    hdr.time_ms = now_ms;
    send_message(hdr, payload, sizeof(payload));
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
    } else if (line == "HS NOW") {
        g_next_hs_ms = 0;
        Serial.println("LOG hs: starting a handshake now");
    } else if (line.startsWith("HS PERIOD ")) {
        // Gateway-local harness line (not in the contract): re-handshake every <ms>.
        long ms = line.substring(10).toInt();
        if (ms >= 2000) {
            g_rehandshake_period_ms = static_cast<uint32_t>(ms);
            Serial.printf("LOG hs: re-handshake period %ld ms\n", ms);
        }
    } else if (line == "HS STATS") {
        Serial.printf("LOG hs stats started=%lu ok=%lu failed=%lu session=%d\n", (unsigned long)g_hs_started,
                      (unsigned long)g_hs_ok, (unsigned long)g_hs_failed, g_session.active);
    }
    // Anything else (e.g. the attacker's MODE lines) is ignored: each board acts on its own.
}

// ---------------------------------------------------------------------
// Mesh frame handling
// ---------------------------------------------------------------------

struct __attribute__((packed)) StatsPayload {
    float pressure_kpa;
    uint32_t spend, challenge, drop, busy_drop, hs_ok, hs_fail;
};

static void on_gate_report(const uint8_t* payload, size_t payload_len) {
    GateReport r;
    if (!deserialize_gate_report(payload, payload_len, r)) {
        Serial.println("LOG malformed GATE_REPORT from field-1 dropped");
        return;
    }
    emit_gate_decision(r);
    if (r.budget_exhausted_edge) {
        emit_budget_exhausted("field-1", "EnergyGate budget exhausted on field-1 -- dropping admissions until it refills");
    }
}

static void on_data(const PacketHeader& hdr, const std::vector<uint8_t>& body, uint32_t now_ms) {
    std::vector<uint8_t> pt;
    OpenResult r = session_open(g_session, hdr, body.data(), body.size(), now_ms, pt);
    switch (r) {
        case OpenResult::OK:
            if (pt.size() == sizeof(StatsPayload)) {
                StatsPayload p;
                memcpy(&p, pt.data(), sizeof(p));
                Serial.printf("LOG field1 pressure=%.2f spend=%lu challenge=%lu drop=%lu busy_drop=%lu hs_ok=%lu hs_fail=%lu\n",
                              p.pressure_kpa, (unsigned long)p.spend, (unsigned long)p.challenge, (unsigned long)p.drop,
                              (unsigned long)p.busy_drop, (unsigned long)p.hs_ok, (unsigned long)p.hs_fail);
            }
            g_window.packets_received++;
            break;
        case OpenResult::DUPLICATE:
            g_window.duplicate_count++;
            break;
        case OpenResult::REPLAY:
            g_window.replay_rej++;
            emit_event("field", "replay_rejected", "medium", node_name_for(hdr.sender), "T1692.002",
                       "Replayed packet rejected", "seq behind replay window");
            break;
        case OpenResult::STALE:
            g_window.stale++;
            break;
        case OpenResult::BAD_TAG:
            g_window.auth_fail++;
            g_window.hs_fail++;
            emit_event("field", "handshake_rejected", "high", node_name_for(hdr.sender), "T0830",
                       "Packet failed AES-GCM authentication", "tag mismatch");
            break;
        default:
            break;   // no session / other epoch
    }
}

static void on_frame(const mesh::Frame& fr) {
    uint32_t now_ms = fr.rx_ms;
    PacketHeader hdr;
    if (!PacketHeader::deserialize(fr.data, fr.len, hdr)) return;
    const uint8_t* payload = fr.data + HEADER_SIZE;
    size_t payload_len = fr.len - HEADER_SIZE;

    g_window.add_rssi(static_cast<float>(fr.rssi));
    g_window.total_received++;

    // This board never hears its own transmissions, so a frame claiming the
    // gateway's id is by definition forged.
    if (hdr.sender == static_cast<uint8_t>(NodeId::GATEWAY)) {
        static uint32_t last_ev_ms = 0;
        if (hdr.type == MsgType::HELLO && hdr.frag_i == 0) {
            g_window.hs_count++;
            g_window.hs_fail++;
            g_window.auth_fail++;
            if (now_ms - last_ev_ms > 2000) {
                last_ev_ms = now_ms;
                emit_event("field", "handshake_rejected", "high", "attacker", "T0830",
                           "HELLO forged with the gateway's identity", "sender id is ours but we did not send it");
            }
        }
        if (hdr.type == MsgType::HELLO) track_hello_frag(hdr, now_ms);
        return;
    }
    if (g_locked_out[hdr.sender]) return;

    switch (hdr.type) {
        case MsgType::HELLO:
            // Overheard on its way to field-1 (the attacker's flood, or a forged field-1 HELLO).
            if (hdr.frag_i == 0) {
                g_window.hs_count++;
                if (hdr.sender == static_cast<uint8_t>(NodeId::FIELD_1)) {
                    // field-1 never initiates: a HELLO claiming its id is an impersonation.
                    g_window.hs_fail++;
                    g_window.auth_fail++;
                    emit_event("field", "handshake_rejected", "high", "attacker", "T0830",
                               "HELLO forged with field-1's identity", "field-1 only ever responds");
                }
            }
            track_hello_frag(hdr, now_ms);
            break;

        case MsgType::CHALLENGE:
            if (hdr.sender == static_cast<uint8_t>(NodeId::FIELD_1) && g_hs_state == HsState::WAIT_RESPONSE &&
                hdr.epoch == g_att.epoch && hdr.seq == g_att.seq && payload_len >= pqc::COOKIE_BYTES) {
                memcpy(g_cookie, payload, pqc::COOKIE_BYTES);
                g_cookie_ready = true;
            }
            break;

        case MsgType::RESPONSE: {
            if (hdr.sender != static_cast<uint8_t>(NodeId::FIELD_1) || g_hs_state != HsState::WAIT_RESPONSE ||
                hdr.epoch != g_att.epoch || hdr.seq != g_att.seq) break;
            std::vector<uint8_t> msg;
            if (!g_reasm.feed(hdr, payload, payload_len, now_ms, msg)) break;
            if (msg.size() != pqc::RESPONSE_LEN) break;
            memcpy(g_resp_rx, msg.data(), msg.size());
            g_resp_rx_len = msg.size();
            g_att.t_resp_ms = now_ms;
            g_hs_state = HsState::PROCESSING;
            if (!crypto_task_submit(job_handle_response, nullptr)) {
                g_hs_state = HsState::WAIT_RESPONSE;   // crypto busy: the RESPONSE is lost, attempt will time out
            }
            break;
        }

        case MsgType::GATE_REPORT:
            if (hdr.sender == static_cast<uint8_t>(NodeId::FIELD_1) && hdr.frag_n == 1) on_gate_report(payload, payload_len);
            break;

        case MsgType::DATA: {
            std::vector<uint8_t> msg;
            if (hdr.frag_n == 1) {
                msg.assign(payload, payload + payload_len);
            } else if (!g_reasm.feed(hdr, payload, payload_len, now_ms, msg)) {
                break;
            }
            on_data(hdr, msg, now_ms);
            break;
        }

        default:
            break;
    }
}

#if SM_PERIPHERALS
static void update_status_display() {
    if (!g_oled_ok) return;
    g_oled.clearDisplay();
    g_oled.setCursor(0, 0);
    g_oled.setTextSize(1);
    g_oled.setTextColor(SSD1306_WHITE);
    const char* status_text = (g_status == StatusColor::FLASHING_RED) ? "TAMPER"
                              : (g_status == StatusColor::STEADY_RED) ? "ATTACK DETECTED"
                              : (g_status == StatusColor::YELLOW) ? "Degraded" : "Secure";
    g_oled.printf("gateway %s+%s\nlabel: %s\ndefence: %s\nhs %lu/%lu ok  %s\n%s\n", SM_PQC_KEM_NAME, SM_PQC_SIG_NAME,
                  g_current_label, defense_mode_name(g_defense), (unsigned long)g_hs_ok,
                  (unsigned long)g_hs_started, g_session.active ? "session" : "no session", status_text);
    g_oled.display();
}
#endif

// ---------------------------------------------------------------------
// Arduino entry points
// ---------------------------------------------------------------------

void setup() {
    Serial.begin(board::CONSOLE_SERIAL_BAUD);
    status_indicators_init();

    Serial.printf("LOG gateway boot: heap free=%u largest_block=%u\n", (unsigned)esp_get_free_heap_size(),
                  (unsigned)heap_caps_get_largest_free_block(MALLOC_CAP_8BIT));
    bool crypto_ok = crypto_task_start(PQC_TASK_STACK_BYTES, 0);   // before Wi-Fi fragments the heap

#if SM_PERIPHERALS
    Wire.begin(board::I2C_SDA, board::I2C_SCL);
    g_oled_ok = g_oled.begin(SSD1306_SWITCHCAPVCC, board::OLED_I2C_ADDR);
    if (g_oled_ok) update_status_display();
#endif

    g_window.reset();
    g_window.window_ms = WINDOW_MS;
    g_window_start_ms = millis();
    g_ctrl_epoch = static_cast<uint16_t>(esp_random());
    g_epoch_ctr = static_cast<uint16_t>(esp_random() | 1);
    memset(g_sets, 0, sizeof(g_sets));

    bool mesh_ok = mesh::init();
    Serial.printf("LOG gateway boot complete: %s+%s crypto_task=%s mesh=%s heap free=%u largest_block=%u\n",
                  SM_PQC_KEM_NAME, SM_PQC_SIG_NAME, crypto_ok ? "ok" : "FAILED", mesh_ok ? "ok" : "FAILED",
                  (unsigned)esp_get_free_heap_size(), (unsigned)heap_caps_get_largest_free_block(MALLOC_CAP_8BIT));
}

void loop() {
    static uint32_t last_stat_ms = 0;

    while (Serial.available()) {
        String line = Serial.readStringUntil('\n');
        line.trim();
        if (line.length() > 0) handle_console_line(line);
    }

    int handled = 0;
    mesh::Frame fr;
    while (handled < 32 && mesh::poll(fr)) { on_frame(fr); handled++; }

    uint32_t now = millis();
    set_status_color(g_status);
    drive_handshake(now);

    if (now - g_last_control_ms >= CONTROL_RESEND_MS) send_control_to_field_node(now);
    if (now - g_window_start_ms >= WINDOW_MS) {
        size_t evicted = g_reasm.expire(now);
        g_window.frag_timeout += static_cast<uint32_t>(evicted);
        expire_hello_sets(now);
        close_detection_window(now);
#if SM_PERIPHERALS
        update_status_display();
#endif
    }
    if (now - last_stat_ms >= 10000) {
        last_stat_ms = now;
        Serial.printf("LOG gw stats hs started=%lu ok=%lu failed=%lu session=%d stack_free_min=%lu rx_overflow=%lu rssi_missing=%lu heap=%u\n",
                      (unsigned long)g_hs_started, (unsigned long)g_hs_ok, (unsigned long)g_hs_failed, g_session.active,
                      (unsigned long)crypto_task_stack_free_min(), (unsigned long)mesh::rx_overflow_count(),
                      (unsigned long)mesh::rssi_missing_count(), (unsigned)esp_get_free_heap_size());
    }
    if (handled == 0) delay(1);
}
