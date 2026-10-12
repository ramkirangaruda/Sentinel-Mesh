// SentinelMesh field node firmware ("field-1": the battery-powered node).
//
// Phase 6 (paper branch): the real radio and the real post-quantum handshake.
//
//  - Transport: ESP-NOW broadcast (common/mesh_transport.*).
//  - Handshake: field-1 is always the RESPONDER. The gateway (initiator) sends
//    a signed HELLO carrying an ephemeral ML-KEM key; field-1 verifies the
//    ML-DSA signature, encapsulates, signs the RESPONSE, and the gateway's
//    CONFIRM completes it (lib/sentinel_pqc/pqc_handshake.h). KEM and signature
//    are paired by NIST level and fixed at compile time (SENTINEL_PQC_LEVEL).
//  - DATA: AES-256-GCM under the session keys, header as AAD (common/msg_io.*).
//  - EnergyGate (brief v4): every HELLO's FIRST fragment goes through the model
//    score + the joule budget + the cookie (gate_policy.h) BEFORE any
//    reassembly or public-key work. SPEND admits the fragment set, CHALLENGE
//    answers with a cookie and waits for it to be echoed, DROP is silence.
//  - The post-quantum work runs in a dedicated task with a large stack
//    (common/crypto_task.*), one handshake at a time.
//
// Build variants:
//   normal                  OLED + tamper sensors + status LED (the demo)
//   SENTINEL_MEASUREMENT_BUILD  none of those (they would be counted as crypto energy)
//   SENTINEL_NO_BATTERY     battery_pct is a fixed 100 -- SIMULATED, there is no cell on the rig
//   SENTINEL_ENERGY_MARKERS GPIO4 high around the gate decision and the handshake
//                           computation, for the Monitor board's energy attribution
//
// Honesty notes (paper/decisions.md): GATE_REPORT / CONTROL are not
// authenticated (lab rig); the cookie proves nothing against an attacker that
// can overhear the CHALLENGE on the shared broadcast medium; the EnergyGate
// model is trained on SIMULATED traces until retrained on recorded ones.

#include <Arduino.h>
#include <Wire.h>
#include <cstring>
#include <vector>
#include <esp_system.h>
#include <esp_heap_caps.h>

#ifndef SENTINEL_MEASUREMENT_BUILD
#define SM_PERIPHERALS 1
#include <Adafruit_MPU6050.h>
#include <Adafruit_Sensor.h>
#include <Adafruit_GFX.h>
#include <Adafruit_SSD1306.h>
#else
#define SM_PERIPHERALS 0
#endif

#include "sentinel_proto/packet.h"
#include "sentinel_proto/fragment.h"
#include "sentinel_proto/cookie.h"
#include "sentinel_proto/energy_budget.h"
#include "sentinel_proto/energygate.h"
#include "sentinel_proto/gate_policy.h"
#include "sentinel_proto/gate_msgs.h"
#include "sentinel_proto/link_window.h"
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
#ifndef DATA_INTERVAL_MS
#define DATA_INTERVAL_MS 3000
#endif
#ifndef GATE_REPORT_MIN_INTERVAL_MS
#define GATE_REPORT_MIN_INTERVAL_MS 200
#endif
#ifndef AWAIT_CONFIRM_MS
#define AWAIT_CONFIRM_MS 4000
#endif
// Per-decision serial logging: handy on the bench, but it costs CPU, so the
// energy builds leave it off.
// SENTINEL_BENCH_LOGS = a measurement-style build (no peripherals) that still prints, for bench testing on USB.
#if defined(SENTINEL_BENCH_LOGS) || (!defined(SENTINEL_MEASUREMENT_BUILD) && !defined(SENTINEL_QUIET_GATE_LOG))
#define GATE_VERBOSE 1
#else
#define GATE_VERBOSE 0
#endif

// ---------------------------------------------------------------------
// State
// ---------------------------------------------------------------------

#if SM_PERIPHERALS
static Adafruit_MPU6050 g_mpu;
static bool g_mpu_ok = false;
static Adafruit_SSD1306 g_oled(board::OLED_WIDTH, board::OLED_HEIGHT, &Wire, -1);
static bool g_oled_ok = false;
static StatusColor g_status = StatusColor::GREEN;
static float g_accel_baseline = 9.8f;
constexpr float ACCEL_TAMPER_DELTA = 2.0f; // m/s^2
static float g_voltage_baseline = -1.0f;
#endif

// v4 EnergyGate state.
static DefenseMode g_defense = DefenseMode::NONE; // the gateway relays the console's mode
// PLACEHOLDER capacity/refill until the INA219 rig measures the real per-handshake cost.
constexpr float ENERGY_BUDGET_CAPACITY_J = 20.0f;
constexpr float ENERGY_BUDGET_REFILL_J_PER_S = 0.05f;
static EnergyBudget g_energy(ENERGY_BUDGET_CAPACITY_J, ENERGY_BUDGET_REFILL_J_PER_S);
static bool g_budget_was_exhausted = false;
static GatePolicyConfig g_gate_cfg;
static CookieChallenge g_cookie(0);   // re-seeded from esp_random() in setup()
static SlidingLink g_link;
static uint32_t g_last_attempt_ms[256] = {0};
static ControlSequencer g_control_seq;

// Reassembly of ADMITTED HELLO sets only (bounded: kMaxAdmitted).
static Reassembler g_reasm;
struct Admit { bool used; uint8_t sender; uint16_t epoch; uint32_t seq; uint32_t expire_ms; };
constexpr int kMaxAdmitted = 2;
static Admit g_admit[kMaxAdmitted];

// Handshake working memory (static: several kB each, never on a task stack).
static pqc::ResponderState g_resp;
static uint8_t g_hello_buf[pqc::HELLO_LEN];
static uint8_t g_resp_buf[pqc::RESPONSE_LEN];
static PhaseTimes g_phase;
struct HsJob { uint8_t peer; uint16_t epoch; uint32_t seq; };
static HsJob g_job;

// (epoch, seq) pairs of HELLOs that have actually VERIFIED, kept per sender in a small ring of
// epochs. Only verified HELLOs are recorded, so an unauthenticated flood cannot fill it and lock
// the real gateway out. Epochs are NOT ordered: a rebooted gateway starts from a random epoch that
// may be lower than before (an earlier version compared epochs numerically and rejected the
// gateway after its first reboot -- found on hardware). A HELLO is a replay only if its exact
// epoch is in the ring with seq <= the recorded one. Limit (see decisions.md): a captured
// signed HELLO whose epoch has aged out of the ring can be replayed once more, costing one full
// handshake; a stateless responder cannot do better without a clock or its own nonce.
struct Verified { bool valid; uint16_t epoch; uint32_t seq; };
constexpr int kVerifiedRing = 8;
static volatile Verified g_verified[4][kVerifiedRing];
static volatile uint8_t g_verified_next[4];

// After RESPONSE is sent we wait for the initiator's CONFIRM.
struct Await { volatile bool active; uint8_t peer; uint16_t epoch; uint32_t seq; uint32_t deadline_ms; };
static Await g_await = {false, 0, 0, 0, 0};

static Session g_session;
static_assert(COOKIE_LEN == pqc::COOKIE_BYTES, "cookie.h and the handshake must agree on the cookie size");

// Counters (loop task unless noted). *_pending are written by the crypto task.
static uint32_t g_n_spend = 0, g_n_challenge = 0, g_n_drop = 0, g_n_busy_drop = 0;
static uint32_t g_n_hs_ok = 0, g_n_hs_fail = 0, g_n_ignored_frags = 0, g_n_unknown_sender = 0;
static uint32_t g_n_replay_pre = 0;
static volatile uint32_t g_hs_fail_pending = 0;
static volatile uint32_t g_hs_sigfail_pending = 0;
static uint32_t g_last_report_ms = 0;
static GateAction g_last_report_action = GateAction::SPEND;
static uint32_t g_rx_overflow_seen = 0;

// ---------------------------------------------------------------------
// Sensors / battery
// ---------------------------------------------------------------------

static float read_pressure_reading() {
    // SIMULATED demo payload (brief v2 honesty rule): the BOM has no pressure sensor.
    static float sim = 101.3f; // kPa
    sim += (random(-10, 11) / 100.0f);
    return sim;
}

static float read_battery_percent() {
#ifdef SENTINEL_NO_BATTERY
    return 100.0f; // SIMULATED: no cell on the paper rig, so this feature is constant
#else
    int raw = analogRead(board::PIN_BATTERY_ADC);
    float vbat = (raw / 4095.0f) * 3.3f * board::BATTERY_DIVIDER_RATIO;
    float pct = (vbat - board::BATTERY_EMPTY_V) / (board::BATTERY_FULL_V - board::BATTERY_EMPTY_V) * 100.0f;
    if (pct < 0) pct = 0;
    if (pct > 100) pct = 100;
    return pct;
#endif
}

#if SM_PERIPHERALS
static bool check_tamper_ldr() { return analogRead(board::PIN_LDR) > board::LDR_TAMPER_THRESHOLD; }
static bool check_tamper_motion() {
    if (!g_mpu_ok) return false;
    sensors_event_t accel, gyro, temp;
    g_mpu.getEvent(&accel, &gyro, &temp);
    float mag = sqrtf(accel.acceleration.x * accel.acceleration.x +
                      accel.acceleration.y * accel.acceleration.y +
                      accel.acceleration.z * accel.acceleration.z);
    return fabsf(mag - g_accel_baseline) > ACCEL_TAMPER_DELTA;
}
static bool check_tamper_reed() { return digitalRead(board::PIN_REED_SWITCH) == HIGH; }
static bool check_tamper_voltage() {
#ifdef SENTINEL_NO_BATTERY
    return false;
#else
    int raw = analogRead(board::PIN_BATTERY_ADC);
    float v = (raw / 4095.0f) * 3.3f * board::BATTERY_DIVIDER_RATIO;
    if (g_voltage_baseline < 0) { g_voltage_baseline = v; return false; }
    bool anomaly = fabsf(v - g_voltage_baseline) > board::VOLTAGE_ANOMALY_DELTA_V;
    g_voltage_baseline += (v - g_voltage_baseline) * 0.02f;
    return anomaly;
#endif
}

static void on_tamper_detected(const char* kind) {
    // Wipe the session keys: a tampered node must not keep talking on old keys.
    g_session.clear();
    g_status = StatusColor::FLASHING_RED;
    buzz_alert();
    Serial.print("LOG tamper detected: ");
    Serial.println(kind);
}
#endif // SM_PERIPHERALS

// ---------------------------------------------------------------------
// Sending
// ---------------------------------------------------------------------

static uint32_t g_ctl_seq = 0;

// Plain (unauthenticated) report/challenge channel -- see header note.
static void send_plain(MsgType type, uint16_t epoch, uint32_t seq, const uint8_t* payload, size_t len) {
    PacketHeader hdr;
    hdr.type = type;
    hdr.sender = static_cast<uint8_t>(NodeId::FIELD_1);
    hdr.epoch = epoch;
    hdr.seq = seq;
    hdr.time_ms = millis();
    send_message(hdr, payload, len);
}

static void report_gate_decision(uint8_t sender, GateAction action, float prob_real,
                                 bool budget_exhausted_edge, uint32_t now_ms) {
    // The report itself is radio traffic on the battery being measured, so it is
    // rate-limited; decisions are counted exactly in the stats payload regardless.
    bool changed = (action != g_last_report_action);
    if (!budget_exhausted_edge && !changed && now_ms - g_last_report_ms < GATE_REPORT_MIN_INTERVAL_MS) return;
    g_last_report_ms = now_ms;
    g_last_report_action = action;

    GateReport r;
    r.sender = sender;
    r.action = action;
    r.mode = g_defense;
    r.budget_exhausted_edge = budget_exhausted_edge;
    r.prob_real = prob_real;
    r.budget_j = g_energy.balance_j();
    r.budget_max_j = g_energy.capacity_j();
    uint8_t buf[GATE_REPORT_LEN];
    serialize_gate_report(r, buf, sizeof(buf));
    send_plain(MsgType::GATE_REPORT, 0, g_ctl_seq++, buf, sizeof(buf));
#if GATE_VERBOSE
    Serial.printf("LOG gate %s sender=%u p=%.2f mode=%s budget=%.2f/%.0fJ\n", gate_action_name(action),
                  sender, prob_real, defense_mode_name(g_defense), g_energy.balance_j(), g_energy.capacity_j());
#endif
}

// Periodic encrypted stats + sensor payload (28 bytes). This is how the
// experiment harness learns the exact decision counts without a serial link.
struct __attribute__((packed)) StatsPayload {
    float pressure_kpa;
    uint32_t spend, challenge, drop, busy_drop, hs_ok, hs_fail;
};

static void send_data(uint32_t now_ms) {
    if (!g_session.active) return;
    StatsPayload p;
    p.pressure_kpa = read_pressure_reading();
    p.spend = g_n_spend; p.challenge = g_n_challenge; p.drop = g_n_drop;
    p.busy_drop = g_n_busy_drop; p.hs_ok = g_n_hs_ok; p.hs_fail = g_n_hs_fail;
    session_send(g_session, static_cast<uint8_t>(NodeId::FIELD_1), MsgType::DATA, now_ms,
                 reinterpret_cast<const uint8_t*>(&p), sizeof(p));
}

// ---------------------------------------------------------------------
// Handshake (responder) -- runs in the crypto task
// ---------------------------------------------------------------------

static const uint8_t* peer_sig_pk(uint8_t sender) {
    switch (sender) {
        case static_cast<uint8_t>(NodeId::GATEWAY):  return demo_keys::SIG_PK_GATEWAY;
        // The attacker board is ENROLLED here on purpose: it models a compromised /
        // insider peer whose HELLOs verify and therefore force a full handshake.
        case static_cast<uint8_t>(NodeId::ATTACKER): return demo_keys::SIG_PK_ATTACKER;
        default: return nullptr;
    }
}

static void crypto_job_hello(void*) {
    const HsJob j = g_job;
    pqc::Hooks hk{phase_probe_hook, &g_phase};
    marker_high();
    pqc::Result r = pqc::responder_handle_hello(g_resp, static_cast<uint8_t>(NodeId::FIELD_1), j.peer,
                                                peer_sig_pk(j.peer), demo_keys::SIG_SK_FIELD1,
                                                g_hello_buf, sizeof(g_hello_buf), hk, g_resp_buf);
    marker_low();
    if (r != pqc::Result::OK) {
        __atomic_fetch_add(&g_hs_fail_pending, 1, __ATOMIC_RELAXED);
        if (r == pqc::Result::BAD_SIGNATURE) __atomic_fetch_add(&g_hs_sigfail_pending, 1, __ATOMIC_RELAXED);
        return;
    }
    if (j.peer < 4) {
        int slot = -1;
        for (int i = 0; i < kVerifiedRing; i++)
            if (g_verified[j.peer][i].valid && g_verified[j.peer][i].epoch == j.epoch) { slot = i; break; }
        if (slot < 0) {
            slot = g_verified_next[j.peer];
            g_verified_next[j.peer] = static_cast<uint8_t>((slot + 1) % kVerifiedRing);
            g_verified[j.peer][slot].epoch = j.epoch;
            g_verified[j.peer][slot].seq = j.seq;
        } else if (j.seq > g_verified[j.peer][slot].seq) {
            g_verified[j.peer][slot].seq = j.seq;
        }
        g_verified[j.peer][slot].valid = true;
    }
    g_await.peer = j.peer; g_await.epoch = j.epoch; g_await.seq = j.seq;
    g_await.deadline_ms = millis() + AWAIT_CONFIRM_MS;
    g_await.active = true;

    PacketHeader h;
    h.type = MsgType::RESPONSE;
    h.sender = static_cast<uint8_t>(NodeId::FIELD_1);
    h.epoch = j.epoch;
    h.seq = j.seq;            // echoes the HELLO so the initiator can match it
    h.time_ms = millis();
    send_message(h, g_resp_buf, sizeof(g_resp_buf));
}

// ---------------------------------------------------------------------
// EnergyGate: admission of one HELLO (fragment 0) -- runs in the loop task
// ---------------------------------------------------------------------

static void build_gate_features(float f[ENERGYGATE_NUM_FEATURES], uint32_t now_ms) {
    g_link.features(f, read_battery_percent(), now_ms);
}

static bool verified_before(const PacketHeader& h) {
    if (h.sender >= 4) return false;
    for (int i = 0; i < kVerifiedRing; i++) {
        if (g_verified[h.sender][i].valid && g_verified[h.sender][i].epoch == h.epoch)
            return h.seq <= g_verified[h.sender][i].seq;   // same epoch, already-used sequence number
    }
    return false;
}

static int admit_slot_free() {
    for (int i = 0; i < kMaxAdmitted; i++) if (!g_admit[i].used) return i;
    return -1;
}
static Admit* admit_find(const PacketHeader& h) {
    for (auto& a : g_admit)
        if (a.used && a.sender == h.sender && a.epoch == h.epoch && a.seq == h.seq) return &a;
    return nullptr;
}

static void on_hello_frag0(const PacketHeader& hdr, const uint8_t* payload, size_t payload_len, uint32_t now_ms) {
    g_link.cur().hs_count++;

    if (peer_sig_pk(hdr.sender) == nullptr) { g_n_unknown_sender++; return; }   // not enrolled: free to drop
    if (verified_before(hdr)) { g_n_replay_pre++; g_link.cur().duplicate_count++; return; }

    // --- EnergyGate decision (everything between the markers is its own cost) ---
    marker_high();
    float f[ENERGYGATE_NUM_FEATURES];
    build_gate_features(f, now_ms);
    GateInputs in;
    in.prob_real = energygate_score(f);
    in.cookie_echoed = (payload_len >= pqc::COOKIE_BYTES) && g_cookie.verify(hdr.sender, now_ms, payload);
    uint32_t last = g_last_attempt_ms[hdr.sender];
    in.ms_since_last_attempt = (last == 0) ? NEVER_SEEN : (now_ms - last);
    g_last_attempt_ms[hdr.sender] = now_ms ? now_ms : 1;
    GateAction action = decide_admission(g_defense, in, g_energy, g_gate_cfg, now_ms);
    marker_low();

    bool exhausted = !g_energy.can_afford(g_gate_cfg.handshake_cost_j, now_ms);
    bool edge = exhausted && !g_budget_was_exhausted && g_defense == DefenseMode::GATE;
    g_budget_was_exhausted = exhausted;

    if (action == GateAction::SPEND) {
        int slot = admit_slot_free();
        if (slot < 0 || crypto_task_busy()) {
            // Cannot take another handshake right now: refuse it, and give back the joules.
            g_n_busy_drop++;
            if (g_defense == DefenseMode::GATE) g_energy.credit(g_gate_cfg.handshake_cost_j);
        } else {
            g_n_spend++;
            g_admit[slot] = {true, hdr.sender, hdr.epoch, hdr.seq, now_ms + REASSEMBLY_TIMEOUT_MS};
            g_link.cur().frag_started++;
            std::vector<uint8_t> unused;
            g_reasm.feed(hdr, payload, payload_len, now_ms, unused);   // fragment 0 of the admitted set
        }
    } else if (action == GateAction::CHALLENGE) {
        g_n_challenge++;
        uint8_t cookie[COOKIE_LEN];
        g_cookie.generate(hdr.sender, CookieChallenge::time_window_for(now_ms), cookie);
        send_plain(MsgType::CHALLENGE, hdr.epoch, hdr.seq, cookie, sizeof(cookie));
    } else {
        g_n_drop++;
    }
    report_gate_decision(hdr.sender, action, in.prob_real, edge, now_ms);
}

static void on_hello_frag(const PacketHeader& hdr, const uint8_t* payload, size_t payload_len, uint32_t now_ms) {
    if (hdr.frag_i == 0) { on_hello_frag0(hdr, payload, payload_len, now_ms); return; }
    Admit* a = admit_find(hdr);
    if (!a) { g_n_ignored_frags++; return; }          // the set was dropped / challenged: ignore the rest
    std::vector<uint8_t> msg;
    if (!g_reasm.feed(hdr, payload, payload_len, now_ms, msg)) return;

    a->used = false;
    g_link.cur().frag_completed++;
    if (msg.size() != pqc::HELLO_LEN) { g_link.cur().hs_fail++; g_n_hs_fail++; return; }
    memcpy(g_hello_buf, msg.data(), msg.size());
    g_job = {hdr.sender, hdr.epoch, hdr.seq};
    if (!crypto_task_submit(crypto_job_hello, nullptr)) g_n_busy_drop++;
}

static void on_confirm(const PacketHeader& hdr, const uint8_t* payload, size_t len, uint32_t now_ms) {
    if (!g_await.active || hdr.sender != g_await.peer || hdr.epoch != g_await.epoch || hdr.seq != g_await.seq) return;
    pqc::SessionKeys keys;
    pqc::Result r = pqc::responder_handle_confirm(g_resp, payload, len, keys);
    g_await.active = false;
    if (r != pqc::Result::OK) {
        g_link.cur().hs_fail++; g_n_hs_fail++;
        Serial.printf("LOG confirm rejected: %s\n", pqc::result_name(r));
        return;
    }
    g_session.peer = hdr.sender;
    g_session.epoch = hdr.epoch;
    memcpy(g_session.k_tx, keys.k_r2i, sizeof(g_session.k_tx));   // responder -> initiator
    memcpy(g_session.k_rx, keys.k_i2r, sizeof(g_session.k_rx));
    g_session.tx_seq = 0;
    g_session.start_ms = now_ms;
    g_session.replay.reset(hdr.sender);
    g_session.active = true;
    g_n_hs_ok++;
    Serial.printf("LOG session established peer=%u epoch=%u (%s+%s) phases_us verify=%lu encaps=%lu sign=%lu stack_free_min=%lu\n",
                  hdr.sender, hdr.epoch, SM_PQC_KEM_NAME, SM_PQC_SIG_NAME,
                  static_cast<unsigned long>(g_phase.us[(int)pqc::Phase::SIG_VERIFY]),
                  static_cast<unsigned long>(g_phase.us[(int)pqc::Phase::KEM_ENCAPS]),
                  static_cast<unsigned long>(g_phase.us[(int)pqc::Phase::SIG_SIGN]),
                  static_cast<unsigned long>(crypto_task_stack_free_min()));
}

static void on_control(const uint8_t* payload, size_t payload_len) {
    ControlMsg m;
    if (!deserialize_control(payload, payload_len, m)) return;
    DefenseMode mode;
    if (m.kind == ControlKind::DEFENSE && defense_mode_from_byte(m.value, mode) && mode != g_defense) {
        g_defense = mode;
        Serial.printf("LOG defence mode set to %s\n", defense_mode_name(g_defense));
    }
}

// Reassembly for the small non-HELLO messages (CONFIRM, CONTROL): single fragment.
static void on_frame(const mesh::Frame& fr) {
    uint32_t now_ms = fr.rx_ms;
    PacketHeader hdr;
    if (!PacketHeader::deserialize(fr.data, fr.len, hdr)) return;
    const uint8_t* payload = fr.data + HEADER_SIZE;
    size_t payload_len = fr.len - HEADER_SIZE;

    if (hdr.sender == static_cast<uint8_t>(NodeId::FIELD_1)) return;   // our own echo / spoof of us
    g_link.add_rssi(static_cast<float>(fr.rssi));
    g_link.cur().total_received++;

    switch (hdr.type) {
        case MsgType::HELLO:
            on_hello_frag(hdr, payload, payload_len, now_ms);
            break;
        case MsgType::CONFIRM:
            if (hdr.frag_n == 1) on_confirm(hdr, payload, payload_len, now_ms);
            break;
        case MsgType::CONTROL:
            // Only from the gateway; ordered by ControlSequencer (see gate_msgs.h). Not authenticated.
            if (hdr.sender == static_cast<uint8_t>(NodeId::GATEWAY) && hdr.frag_n == 1) {
                if (g_control_seq.accept(hdr.epoch, hdr.seq)) on_control(payload, payload_len);
                else g_link.cur().duplicate_count++;
            }
            break;
        default:
            break;   // RESPONSE/CHALLENGE/GATE_REPORT are not for the responder
    }
}

static void housekeeping(uint32_t now_ms) {
    g_energy.tick(now_ms);
    g_link.advance(now_ms);

    // Fold in the crypto task's counters and the radio's overflow count.
    uint32_t fails = __atomic_exchange_n(&g_hs_fail_pending, 0, __ATOMIC_RELAXED);
    if (fails) { g_link.cur().hs_fail += fails; g_n_hs_fail += fails; }
    uint32_t ov = mesh::rx_overflow_count();
    if (ov != g_rx_overflow_seen) { g_link.cur().lost += ov - g_rx_overflow_seen; g_rx_overflow_seen = ov; }

    size_t evicted = g_reasm.expire(now_ms);
    (void)evicted;
    for (auto& a : g_admit) if (a.used && now_ms > a.expire_ms) a.used = false;

    if (g_await.active && now_ms > g_await.deadline_ms) {
        g_await.active = false;          // half-open handshake: counts as a failed one
        g_link.cur().hs_fail++; g_n_hs_fail++;
    }
}

#if SM_PERIPHERALS
static void update_status_display(float battery_pct) {
    if (!g_oled_ok) return;
    g_oled.clearDisplay();
    g_oled.setCursor(0, 0);
    g_oled.setTextSize(1);
    g_oled.setTextColor(SSD1306_WHITE);
    const char* status_text = (g_status == StatusColor::FLASHING_RED) ? "TAMPER"
                              : g_session.active ? "Secure" : "No session";
    g_oled.printf("%s+%s\nBatt %d%% | %s\ngate:%s %d/%dJ\nhs ok %lu fail %lu\n", SM_PQC_KEM_NAME, SM_PQC_SIG_NAME,
                  static_cast<int>(battery_pct), status_text, defense_mode_name(g_defense),
                  static_cast<int>(g_energy.balance_j()), static_cast<int>(g_energy.capacity_j()),
                  static_cast<unsigned long>(g_n_hs_ok), static_cast<unsigned long>(g_n_hs_fail));
    g_oled.display();
}
#endif

// ---------------------------------------------------------------------
// Arduino entry points
// ---------------------------------------------------------------------

void setup() {
    Serial.begin(board::CONSOLE_SERIAL_BAUD);
    randomSeed(esp_random());

    Serial.printf("LOG field_node boot: heap free=%u largest_block=%u\n", (unsigned)esp_get_free_heap_size(),
                  (unsigned)heap_caps_get_largest_free_block(MALLOC_CAP_8BIT));
    // FIRST, before Wi-Fi fragments the heap: reserve the big crypto stack.
    bool crypto_ok = crypto_task_start(PQC_TASK_STACK_BYTES, 0);

    pinMode(board::PIN_ENERGY_MARKER, OUTPUT);
    digitalWrite(board::PIN_ENERGY_MARKER, LOW);
#if SM_PERIPHERALS
    pinMode(board::PIN_LDR, INPUT);
    pinMode(board::PIN_REED_SWITCH, INPUT_PULLUP);
    pinMode(board::PIN_BTN_URGENT, INPUT_PULLUP);
    pinMode(board::PIN_BTN_AUX, INPUT);
    pinMode(board::PIN_BATTERY_ADC, INPUT);
    status_indicators_init();
    Wire.begin(board::I2C_SDA, board::I2C_SCL);
    g_mpu_ok = g_mpu.begin();
    if (g_mpu_ok) {
        sensors_event_t accel, gyro, temp;
        g_mpu.getEvent(&accel, &gyro, &temp);
        g_accel_baseline = sqrtf(accel.acceleration.x * accel.acceleration.x +
                                 accel.acceleration.y * accel.acceleration.y +
                                 accel.acceleration.z * accel.acceleration.z);
    }
    g_oled_ok = g_oled.begin(SSD1306_SWITCHCAPVCC, board::OLED_I2C_ADDR);
#endif

    g_cookie = CookieChallenge(esp_random());
    g_link.reset(millis());
    memset(const_cast<Verified*>(&g_verified[0][0]), 0, sizeof(g_verified));
    memset(const_cast<uint8_t*>(g_verified_next), 0, sizeof(g_verified_next));
    bool mesh_ok = mesh::init();

    Serial.printf("LOG field_node ready: %s+%s crypto_task=%s mesh=%s EnergyGate scorer=%s defence=%s heap free=%u largest_block=%u\n",
                  SM_PQC_KEM_NAME, SM_PQC_SIG_NAME, crypto_ok ? "ok" : "FAILED", mesh_ok ? "ok" : "FAILED",
                  energygate_uses_trained_model() ? "trained model" : "rule-based stand-in",
                  defense_mode_name(g_defense), (unsigned)esp_get_free_heap_size(),
                  (unsigned)heap_caps_get_largest_free_block(MALLOC_CAP_8BIT));
#ifdef SENTINEL_NO_BATTERY
    Serial.println("LOG battery_pct is a fixed 100 (SIMULATED: no cell on this rig)");
#endif
}

void loop() {
    static uint32_t last_data_ms = 0;
    static uint32_t last_display_ms = 0;
    static uint32_t last_stat_ms = 0;

    int handled = 0;
    mesh::Frame fr;
    while (handled < 32 && mesh::poll(fr)) { on_frame(fr); handled++; }

    uint32_t now = millis();
    housekeeping(now);

#if SM_PERIPHERALS
    if (check_tamper_ldr())     { on_tamper_detected("case_opened");     delay(1000); }
    if (check_tamper_motion())  { on_tamper_detected("moved");           delay(1000); }
    if (check_tamper_reed())    { on_tamper_detected("case_opened");     delay(1000); }
    if (check_tamper_voltage()) { on_tamper_detected("voltage_anomaly"); delay(1000); }
    if (g_status != StatusColor::FLASHING_RED && g_status != StatusColor::STEADY_RED)
        g_status = g_session.active ? StatusColor::GREEN : StatusColor::YELLOW;
    set_status_color(g_status);
    if (now - last_display_ms >= 1000) { update_status_display(read_battery_percent()); last_display_ms = now; }
#else
    (void)last_display_ms;
#endif

    if (now - last_data_ms >= DATA_INTERVAL_MS) { send_data(now); last_data_ms = now; }

#if GATE_VERBOSE
    if (now - last_stat_ms >= 10000) {
        last_stat_ms = now;
        Serial.printf("LOG stats spend=%lu challenge=%lu drop=%lu busy=%lu hs_ok=%lu hs_fail=%lu unknown=%lu replay_pre=%lu ignored_frags=%lu rx_overflow=%lu rssi_missing=%lu heap=%u\n",
                      (unsigned long)g_n_spend, (unsigned long)g_n_challenge, (unsigned long)g_n_drop,
                      (unsigned long)g_n_busy_drop, (unsigned long)g_n_hs_ok, (unsigned long)g_n_hs_fail,
                      (unsigned long)g_n_unknown_sender, (unsigned long)g_n_replay_pre,
                      (unsigned long)g_n_ignored_frags, (unsigned long)mesh::rx_overflow_count(),
                      (unsigned long)mesh::rssi_missing_count(), (unsigned)esp_get_free_heap_size());
    }
#else
    (void)last_stat_ms;
#endif

    if (handled == 0) delay(1);   // nothing to do: yield (the radio and crypto task run elsewhere)
}
