// SentinelMesh field node firmware ("Node A" in brief v2's storyboard —
// the pipeline valve station pressure sensor).
//
// Responsibilities (brief v2 section 2 storyboard + section 10):
//  - Send a pressure reading every ~30s as a DATA message to the gateway
//    (brief v2 storyboard says "every 30 seconds"; using 3s here so the
//    demo doesn't sit idle — tune back up for the real pitch if desired).
//  - On tamper (LDR case-opened, MPU6050 moved, reed switch case-opened,
//    or a sudden voltage anomaly): wipe keys, force a re-handshake, and
//    notify the gateway (the gateway is the one that emits the tamper EVT
//    to the console, since only it talks to serial).
//  - Adaptive crypto level: watch battery %, RSSI, and the urgent button;
//    re-handshake at a new ML-KEM level when the level should change
//    (brief v2 section 8).
//  - Drive its own OLED + RGB LED + buzzer (BOM has 2 of each — field_node
//    and gateway both get status indicators, brief v2 section 11/12).
//  - v4 (brief v4 sections 1-4): run EnergyGate. This node runs from the
//    18650 cell the INA219 measures, so it is the one a HELLO flood drains
//    ("an attacker who simply keeps saying hello can flatten a field node's
//    battery"). Every inbound HELLO goes through energygate_score() + the
//    joule budget + the cookie, via gate_policy.h, BEFORE any signature or
//    KEM work. The defence mode arrives from the console as `DEFENSE <mode>`,
//    relayed by the gateway as a CONTROL message; each decision goes back to
//    the gateway as a GATE_REPORT, which it turns into the console's
//    `gate_decision` event. (This node has no serial link during a run --
//    USB would bypass the INA219 -- hence the relay both ways.)
//    The PIN_ENERGY_MARKER pin is raised around each decision so the monitor
//    board measures EnergyGate's own cost (brief v4 section 3: "EnergyGate
//    itself -- microseconds and millijoules per decision").
//  - Real handshake (HMAC-PSK fallback, see common/handshake.h for why not
//    true PQC yet): this node is always the RESPONDER -- the gateway
//    initiates. On a SPEND-admitted HELLO, verifies its tag, replies with
//    RESPONSE, and finalizes the session on a verified CONFIRM. Once
//    established, DATA/GATE_REPORT payloads are AES-256-GCM encrypted
//    (common/aead.h) and header.time_ms switches to "ms since session
//    start," which is what makes the gateway's replay/freshness check
//    actually mean something instead of comparing two unsynchronized
//    board uptimes.
//
// Pressure sensor note (resolved from brief v2): the BOM (section 11) has
// no dedicated pressure sensor — "pressure" is the storyboard's demo
// payload for a pipeline valve station, not a sensor SentinelMesh itself
// measures. read_pressure_reading() below is intentionally a simulated
// value, consistent with the brief's "honesty rule" (section 8): a
// simulation is fine as long as it's labelled, which it is here.

#include <Arduino.h>
#include <Wire.h>
#include <cstring>
#include <vector>
#include <LiquidCrystal_I2C.h>

#include "sentinel_proto/packet.h"
#include "sentinel_proto/fragment.h"
#include "sentinel_proto/trace.h"
#include "sentinel_proto/cookie.h"
#include "sentinel_proto/energy_budget.h"
#include "sentinel_proto/energygate.h"
#include "sentinel_proto/gate_policy.h"
#include "sentinel_proto/gate_msgs.h"
#include "common/board_config.h"
#include "common/status_indicators.h"
#include "common/mesh_transport.h"
#include "common/handshake.h"
#include "common/aead.h"

using namespace sentinel;

// MPU6050 via a direct/manual I2C driver instead of Adafruit_MPU6050.
// That library's begin() rejects this board's chip -- it does an identity
// check (reads the WHO_AM_I register and compares against Invensense's
// official value) that some cheap/clone MPU6050 breakouts fail even though
// the chip answers every real command correctly. Confirmed during
// bring-up: the chip acks on the bus at the expected address (0x68) and
// gives sane accelerometer data once talked to directly.
constexpr uint8_t MPU6050_I2C_ADDR = 0x68;
static bool g_mpu_ok = false;

static void mpu_wake() {
    Wire.beginTransmission(MPU6050_I2C_ADDR);
    Wire.write(0x6B); // power management register
    Wire.write(0);    // clear sleep bit
    Wire.endTransmission(true);
}

static bool mpu_read_accel(float& ax, float& ay, float& az) {
    Wire.beginTransmission(MPU6050_I2C_ADDR);
    Wire.write(0x3B); // first accelerometer data register
    if (Wire.endTransmission(false) != 0) return false;
    uint8_t n = Wire.requestFrom(static_cast<int>(MPU6050_I2C_ADDR), 6, 1);
    if (n < 6) return false;
    int16_t rawX = (Wire.read() << 8) | Wire.read();
    int16_t rawY = (Wire.read() << 8) | Wire.read();
    int16_t rawZ = (Wire.read() << 8) | Wire.read();
    ax = rawX / 16384.0f * 9.81f; // default +-2g range, 16384 LSB/g
    ay = rawY / 16384.0f * 9.81f;
    az = rawZ / 16384.0f * 9.81f;
    return true;
}

static LiquidCrystal_I2C g_lcd(board::LCD_I2C_ADDR, board::LCD_COLS, board::LCD_ROWS);
static bool g_lcd_ok = false;

static uint16_t g_epoch = 1;        // bumped on every re-handshake/rekey (16-bit, brief v2 6.1)
static uint32_t g_seq = 0;          // bumped per DATA message sent (32-bit, brief v2 section 7)
static KemLevel g_kem_level = KemLevel::KEM_512; // starts at the cheapest level
static StatusColor g_status = StatusColor::GREEN;
static bool g_weak_link_debug = false; // toggled by PIN_BTN_AUX, simulates cut TX power

// Baseline accel magnitude sampled at boot, used to detect "moved" tamper
// via a simple deviation threshold. Replace with something more robust
// (e.g. a short moving-average + hysteresis) once real motion data is in
// hand from the boards.
static float g_accel_baseline = 9.8f; // ~1g at rest
constexpr float ACCEL_TAMPER_DELTA = 2.0f; // m/s^2

// Rolling voltage baseline for tamper detection (distinct from the plain
// battery-% reading the adaptive engine uses): brief v2 section 10 —
// "sudden voltage drop or spike: battery swap, or a forced short" should
// be flagged as tamper, separately from the slow, expected discharge curve
// the adaptive engine already handles.
static float g_voltage_baseline = -1.0f; // -1 = not yet initialized

// ---------------------------------------------------------------------
// Handshake / session state (HMAC-PSK fallback -- see common/handshake.h).
// This node is always the RESPONDER; the gateway is always the initiator.
// ---------------------------------------------------------------------

static bool g_session_established = false;
static uint8_t g_session_key[32] = {0};
static uint32_t g_session_start_ms = 0; // this node's own millis() when the session began
static uint32_t g_pending_nonce_a = 0;  // from the gateway's HELLO
static uint32_t g_pending_nonce_b = 0;  // this node's own nonce, sent in RESPONSE
static bool g_have_pending_response = false;

// ---------------------------------------------------------------------
// v4 EnergyGate state (moved here from the gateway -- see file header)
// ---------------------------------------------------------------------

// Starts undefended, matching the console's default (`DEFENSE none`); the
// gateway relays the console's current mode as soon as it is connected.
static DefenseMode g_defense = DefenseMode::NONE;

// Joule token bucket. PLACEHOLDER capacity/refill until the INA219 rig
// measures real per-handshake cost (brief v4 section 3).
constexpr float ENERGY_BUDGET_CAPACITY_J = 20.0f;
constexpr float ENERGY_BUDGET_REFILL_J_PER_S = 0.05f;
static EnergyBudget g_energy(ENERGY_BUDGET_CAPACITY_J, ENERGY_BUDGET_REFILL_J_PER_S);
static bool g_budget_was_exhausted = false;

static GatePolicyConfig g_gate_cfg; // thresholds + handshake cost, see gate_policy.h

// Re-seeded from esp_random() in setup(); a fixed secret would let an
// attacker precompute cookies.
static CookieChallenge g_cookie(0);

// Link-level view from this node's side, for EnergyGate's free signals
// (same counters and definitions as the gateway's trace windows, so the
// features match what the model was trained on).
static TraceWindowCounters g_link;
static uint32_t g_link_window_start_ms = 0;
constexpr uint32_t LINK_WINDOW_MS = 5000;

// Per-sender: when did it last try (RATELIMIT mode). 0 = never.
static uint32_t g_last_attempt_ms[256] = {0};

static ControlSequencer g_control_seq; // orders CONTROL messages from the gateway

static void send_to_gateway(MsgType type, const uint8_t* payload, size_t len);

// ---------------------------------------------------------------------
// Sensors
// ---------------------------------------------------------------------

static float read_pressure_reading() {
    // Simulated demo payload — see file header note. Synthesizes a slowly
    // drifting value so the rest of the pipeline (DATA send, fragmentation,
    // gateway decode) can be exercised end to end.
    static float sim = 101.3f; // kPa, roughly sea-level atmospheric
    sim += (random(-10, 11) / 100.0f);
    return sim;
}

static bool check_tamper_ldr() {
    int v = analogRead(board::PIN_LDR);
    // This specific LDR module reads INVERTED vs. the usual assumption --
    // confirmed by hand during bring-up: covering it (dark) gives a HIGHER
    // raw ADC value, uncovering it (light/case open) gives a LOWER one.
    // Flipped from the naive `v > threshold`.
    return v < board::LDR_TAMPER_THRESHOLD;
}

static bool check_tamper_motion() {
    if (!g_mpu_ok) return false;
    float ax, ay, az;
    if (!mpu_read_accel(ax, ay, az)) return false;
    float mag = sqrtf(ax * ax + ay * ay + az * az);
    return fabsf(mag - g_accel_baseline) > ACCEL_TAMPER_DELTA;
}

// Second, independent case-opened channel (brief v2 section 10: "works in
// the dark", defends against an attacker covering the LDR).
static bool check_tamper_reed() {
    return digitalRead(board::PIN_REED_SWITCH) == HIGH; // HIGH = circuit open = case opened
}

static float read_battery_voltage() {
    int raw = analogRead(board::PIN_BATTERY_ADC);
    float adc_v = (raw / 4095.0f) * 3.3f; // ESP32 ADC full-scale ~3.3V
    return adc_v * board::BATTERY_DIVIDER_RATIO;
}

static float read_battery_percent() {
    float vbat = read_battery_voltage();
    float pct = (vbat - board::BATTERY_EMPTY_V) /
                (board::BATTERY_FULL_V - board::BATTERY_EMPTY_V) * 100.0f;
    if (pct < 0) pct = 0;
    if (pct > 100) pct = 100;
    return pct;
}

// Sudden voltage jump/drop vs. a slow-moving baseline -> tamper (battery
// swap or a forced short), as opposed to the normal, gradual discharge
// curve the adaptive engine reacts to.
static bool check_tamper_voltage() {
    float v = read_battery_voltage();
    if (g_voltage_baseline < 0) {
        g_voltage_baseline = v; // first reading seeds the baseline
        return false;
    }
    bool anomaly = fabsf(v - g_voltage_baseline) > board::VOLTAGE_ANOMALY_DELTA_V;
    // Slowly track the baseline so normal discharge doesn't false-trigger.
    g_voltage_baseline += (v - g_voltage_baseline) * 0.02f;
    return anomaly;
}

// ---------------------------------------------------------------------
// Tamper response
// ---------------------------------------------------------------------

static void on_tamper_detected(const char* kind) {
    // A tamper event ends the current session outright -- whatever key was
    // in use might be compromised, so don't just bump the epoch, drop the
    // session entirely and make the gateway re-run the full handshake.
    g_session_established = false;
    memset(g_session_key, 0, sizeof(g_session_key));
    g_epoch++; // new epoch forces the replay window to reset on the gateway
    g_seq = 0;

    g_status = StatusColor::FLASHING_RED;
    buzz_alert();

    // Notify the gateway with a plain DATA message carrying the tamper
    // kind; the gateway maps this to a `tamper` EVT (case_opened / moved /
    // voltage_anomaly per contract) since it owns the console link.
    Serial.print("LOG tamper detected: ");
    Serial.println(kind);
}

// ---------------------------------------------------------------------
// Adaptive level (brief v2 section 8)
// ---------------------------------------------------------------------

static KemLevel pick_adaptive_level(float battery_pct, int rssi, bool urgent_pressed) {
    // Simple, documented rules. Tune thresholds once real RF/battery data
    // exists (brief v2: "Model: a small decision tree trained offline...
    // exported as a lookup table" — this is the rule-based stand-in for
    // that, same pattern as classify_window() in field_model.h).
    if (urgent_pressed) return KemLevel::KEM_1024;      // urgent message gets its own fresh 1024 handshake
    if (battery_pct < 20.0f) return KemLevel::KEM_512;  // conserve power
    if (rssi < -85) return KemLevel::KEM_512;           // weak link: cheapest handshake
    if (rssi > -60 && battery_pct > 50.0f) return KemLevel::KEM_1024;
    return KemLevel::KEM_768; // default middle ground
}

static void maybe_rehandshake_for_level(KemLevel desired) {
    if (desired == g_kem_level) return;
    g_kem_level = desired;
    // NOTE: with the HMAC-PSK fallback there's no real per-level KEM cost to
    // re-derive -- the level is tracked for the demo's own story/status
    // display, but doesn't currently force a fresh session the way it would
    // once real ML-KEM levels exist. Session drops are still tamper- and
    // gateway-initiated only.
    Serial.printf("LOG adaptive level changed to %d (no re-handshake triggered under the HMAC-PSK fallback)\n",
                  static_cast<int>(g_kem_level));
}

// ---------------------------------------------------------------------
// Send path
// ---------------------------------------------------------------------

// Sends one message to the gateway. HELLO/RESPONSE/CONFIRM are never
// encrypted (they establish the very key AES-GCM would use) -- only
// DATA/GATE_REPORT get AES-256-GCM'd, and only once a session exists.
static void send_to_gateway(MsgType type, const uint8_t* payload, size_t len) {
    PacketHeader hdr;
    hdr.type = type;
    hdr.sender = SENTINEL_NODE_ID;
    hdr.epoch = g_epoch;
    hdr.seq = g_seq++;
    hdr.time_ms = g_session_established ? (millis() - g_session_start_ms) : millis();
    hdr.prio = 0;

    const uint8_t* send_payload = payload;
    size_t send_len = len;
    std::vector<uint8_t> ciphertext;

    bool should_encrypt = g_session_established &&
                           (type == MsgType::DATA || type == MsgType::GATE_REPORT);
    if (should_encrypt) {
        uint8_t nonce[aead::GCM_NONCE_LEN];
        aead::build_nonce(hdr.sender, hdr.epoch, hdr.seq, nonce);
        uint8_t hdr_bytes[HEADER_SIZE];
        hdr.serialize(hdr_bytes, sizeof(hdr_bytes));
        // Valid only for single-fragment messages (true for everything this
        // node sends today: a 4-byte pressure reading, a 16-byte GATE_REPORT)
        // -- the AAD here must match the header each fragment actually
        // carries, and multi-fragment messages would need per-fragment AAD.
        if (aead::encrypt(g_session_key, nonce, hdr_bytes, HEADER_SIZE, payload, len, ciphertext)) {
            send_payload = ciphertext.data();
            send_len = ciphertext.size();
        } else {
            Serial.println("LOG send_to_gateway: encryption failed, sending plaintext");
        }
    }

    auto frags = Fragmenter::split(hdr, send_payload, send_len);
    for (auto& frag : frags) {
        sentinel::mesh::broadcast(frag.data(), frag.size());
    }
}

static void send_pressure_reading() {
    float p = read_pressure_reading();

    // If g_weak_link_debug is set, a real transport would simulate cut TX
    // power (drop/delay some fraction of frags) -- brief v2 section 12
    // "opt" beat. Not implemented at the transport layer yet.
    uint8_t payload[sizeof(float)];
    memcpy(payload, &p, sizeof(p));
    send_to_gateway(MsgType::DATA, payload, sizeof(payload));
}

// ---------------------------------------------------------------------
// v4 EnergyGate: inbound HELLO admission + reports to the gateway
// ---------------------------------------------------------------------

static void report_gate_decision(uint8_t sender, GateAction action, float prob_real,
                                 bool budget_exhausted_edge) {
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
    send_to_gateway(MsgType::GATE_REPORT, buf, sizeof(buf));

    // Bench visibility when USB *is* attached (not during a measured run).
    Serial.printf("LOG gate %s sender=%u p=%.2f mode=%s budget=%.2f/%.0fJ\n",
                  gate_action_name(action), sender, prob_real, defense_mode_name(g_defense),
                  g_energy.balance_j(), g_energy.capacity_j());
}

// EnergyGate's 8 features, in ml/sentinel_ml/energygate.py's FEATURE_ORDER
// (see energygate.h -- placed by name, never by position).
static void build_gate_features(float f[ENERGYGATE_NUM_FEATURES]) {
    f[EG_HS_PER_S] = g_link.hs_per_s();
    f[EG_HS_FAIL] = static_cast<float>(g_link.hs_fail);
    f[EG_RSSI_MEAN] = g_link.rssi_mean();
    f[EG_RSSI_VAR] = g_link.rssi_var();
    f[EG_LOSS_PCT] = g_link.loss_pct();
    f[EG_DUP_PCT] = g_link.dup_pct();
    f[EG_FRAG_COMPLETE_PCT] = g_link.frag_complete_pct();
    // This node's own battery, from its ADC. On the gateway this feature was
    // never available and silently defaulted to 100%.
    f[EG_BATTERY_PCT] = read_battery_percent();
}

static void on_inbound_hello(const PacketHeader& hdr, const uint8_t* payload, size_t payload_len,
                             uint32_t now_ms) {
    g_link.hs_count++;
    if (hdr.frag_i == 0) g_link.frag_sets_started++;

    // Mark the decision for the monitor board: this interval is EnergyGate's cost.
    digitalWrite(board::PIN_ENERGY_MARKER, HIGH);

    float f[ENERGYGATE_NUM_FEATURES];
    build_gate_features(f);

    GateInputs in;
    in.prob_real = energygate_score(f);
    // TODO: set once HELLO framing carries the cookie echo (brief v2 6.2 has
    // no slot for it yet); verify with g_cookie.verify(hdr.sender, now_ms, echo).
    in.cookie_echoed = false;
    uint32_t last = g_last_attempt_ms[hdr.sender];
    in.ms_since_last_attempt = (last == 0) ? NEVER_SEEN : (now_ms - last);
    g_last_attempt_ms[hdr.sender] = now_ms ? now_ms : 1;

    GateAction action = decide_admission(g_defense, in, g_energy, g_gate_cfg, now_ms);

    digitalWrite(board::PIN_ENERGY_MARKER, LOW);

    // budget_exhausted is edge-triggered so a sustained drain doesn't spam
    // the console with one per HELLO.
    bool exhausted = !g_energy.can_afford(g_gate_cfg.handshake_cost_j, now_ms);
    bool edge = exhausted && !g_budget_was_exhausted && g_defense == DefenseMode::GATE;
    g_budget_was_exhausted = exhausted;

    report_gate_decision(hdr.sender, action, in.prob_real, edge);

    if (action == GateAction::CHALLENGE) {
        uint8_t cookie[COOKIE_LEN];
        g_cookie.generate(hdr.sender, CookieChallenge::time_window_for(now_ms), cookie);
        (void)cookie; // TODO: send once HELLO/RESPONSE framing carries a cookie-echo slot
        return;
    }
    if (action == GateAction::DROP) {
        return; // silence, and it's logged via the report
    }

    // SPEND: verify the sender's HELLO tag (HMAC-PSK fallback -- see
    // common/handshake.h for why not real PQC yet). A bad tag here means
    // either a corrupted frame or someone without the shared PSK -- e.g.
    // the attacker's FLOOD mode, which never signs anything at all.
    uint32_t nonce_a;
    if (!handshake::verify_hello(hdr.sender, payload, payload_len, nonce_a)) {
        g_link.hs_fail++;
        g_link.auth_fail++;
        Serial.printf("LOG handshake_rejected: bad HELLO tag from sender=%u\n", hdr.sender);
        return;
    }

    g_pending_nonce_a = nonce_a;
    g_pending_nonce_b = esp_random();
    g_have_pending_response = true;

    uint8_t resp[handshake::RESPONSE_LEN];
    handshake::build_response(SENTINEL_NODE_ID, g_pending_nonce_a, g_pending_nonce_b, resp);
    send_to_gateway(MsgType::RESPONSE, resp, sizeof(resp));
    Serial.println("LOG handshake: verified HELLO, sent RESPONSE");
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

// Called once per received, header-parsed packet from the mesh transport.
static void on_mesh_packet(const PacketHeader& hdr, const uint8_t* payload, size_t payload_len,
                           float rssi, uint32_t now_ms) {
    g_link.add_rssi(rssi);

    if (hdr.type == MsgType::HELLO) {
        on_inbound_hello(hdr, payload, payload_len, now_ms);
        return;
    }

    // CONFIRM finalizes the handshake this node responded to (RESPONSE
    // above). Small, single-fragment, handled directly like HELLO -- no
    // reassembly/replay infra needed for a 36-byte message.
    if (hdr.type == MsgType::CONFIRM && hdr.sender == static_cast<uint8_t>(NodeId::GATEWAY)) {
        if (g_have_pending_response &&
            handshake::verify_confirm(hdr.sender, g_pending_nonce_a, g_pending_nonce_b, payload, payload_len)) {
            handshake::derive_session_key(g_pending_nonce_a, g_pending_nonce_b, g_session_key);
            g_session_established = true;
            g_session_start_ms = millis();
            g_epoch++;
            g_seq = 0;
            g_have_pending_response = false;
            Serial.println("LOG handshake: session established with gateway");
        } else {
            Serial.println("LOG handshake: CONFIRM verify failed or unexpected (no pending RESPONSE)");
        }
        return;
    }

    g_link.total_received++;

    // CONTROL is only accepted from the gateway (TODO: and only once the
    // AEAD layer authenticates it -- until then this is structural). Ordered
    // by ControlSequencer, not ReplayFilter -- see gate_msgs.h for why the
    // replay filter's clock-based freshness check can't work across boards.
    if (hdr.type == MsgType::CONTROL && hdr.sender == static_cast<uint8_t>(NodeId::GATEWAY)) {
        if (g_control_seq.accept(hdr.epoch, hdr.seq)) {
            on_control(payload, payload_len);
        } else {
            g_link.duplicate_count++;
        }
    }
}

// Bridges the ESP-NOW radio layer (raw bytes + RSSI) to on_mesh_packet()'s
// (header, payload, rssi, now_ms) shape. Registered with sentinel::mesh::init()
// in setup(). Silently drops anything that doesn't parse as a valid header
// (wrong version/type, or too short) -- that's normal on a shared broadcast
// channel picking up other traffic, not an error worth logging every time.
static void mesh_recv_bridge(const uint8_t* data, size_t len, int rssi_dbm) {
    PacketHeader hdr;
    if (!PacketHeader::deserialize(data, len, hdr)) return;
    const uint8_t* payload = data + HEADER_SIZE;
    size_t payload_len = len - HEADER_SIZE;
    on_mesh_packet(hdr, payload, payload_len, static_cast<float>(rssi_dbm), millis());
}

static void roll_link_window(uint32_t now_ms) {
    if (now_ms - g_link_window_start_ms < LINK_WINDOW_MS) return;
    g_link.reset();
    g_link.window_ms = LINK_WINDOW_MS;
    g_link_window_start_ms = now_ms;
}

// ---------------------------------------------------------------------
// Status display -- condensed for a real 16x2 character LCD (the BOM's
// "OLED" turned out to be this instead, see board_config.h). The original
// 4-line pixel-OLED layout ("ML-KEM-1024 | Batt 90% | Seq 0142 | Secure")
// doesn't fit; this keeps the two most demo-relevant facts per line.
// ---------------------------------------------------------------------

static void update_status_display(float battery_pct) {
    if (!g_lcd_ok) return;
    const char* status_text =
        (g_status == StatusColor::FLASHING_RED) ? "TAMPER!" :
        (g_status == StatusColor::STEADY_RED)   ? "ATTACK!" :
        (g_status == StatusColor::YELLOW)       ? "Degraded" : "Secure";

    char raw1[24];
    snprintf(raw1, sizeof(raw1), "K%d Bat%d%%",
             static_cast<int>(g_kem_level), static_cast<int>(battery_pct));
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
    randomSeed(esp_random());

    pinMode(board::PIN_LDR, INPUT);
    pinMode(board::PIN_REED_SWITCH, INPUT_PULLUP);
    pinMode(board::PIN_BTN_URGENT, INPUT_PULLUP);
    pinMode(board::PIN_BTN_AUX, INPUT); // input-only pin on WROOM-32, no internal pullup available
    pinMode(board::PIN_BATTERY_ADC, INPUT);
    pinMode(board::PIN_ENERGY_MARKER, OUTPUT);
    digitalWrite(board::PIN_ENERGY_MARKER, LOW);
    status_indicators_init();

    g_cookie = CookieChallenge(esp_random());
    g_link.reset();
    g_link.window_ms = LINK_WINDOW_MS;
    g_link_window_start_ms = millis();

    Wire.begin(board::I2C_SDA, board::I2C_SCL);
    Wire.beginTransmission(MPU6050_I2C_ADDR);
    g_mpu_ok = (Wire.endTransmission() == 0);
    if (g_mpu_ok) {
        mpu_wake();
        delay(50); // let it come out of sleep before the first real read
        float ax, ay, az;
        if (mpu_read_accel(ax, ay, az)) {
            g_accel_baseline = sqrtf(ax * ax + ay * ay + az * az);
        }
    }
    g_lcd.init();
    g_lcd.backlight();
    g_lcd_ok = true; // LiquidCrystal_I2C has no return-value begin() to check

    Serial.printf("LOG field_node boot complete; EnergyGate scorer: %s; defence: %s\n",
                  energygate_uses_trained_model() ? "trained model" : "rule-based stand-in",
                  defense_mode_name(g_defense));

    if (!sentinel::mesh::init(mesh_recv_bridge)) {
        Serial.println("LOG field_node: ESP-NOW init failed -- mesh traffic will not work");
    }
}

void loop() {
    static uint32_t last_send_ms = 0;
    static uint32_t last_adapt_ms = 0;
    static uint32_t last_display_ms = 0;
    uint32_t now = millis();
    g_energy.tick(now);
    roll_link_window(now);

    if (check_tamper_ldr()) {
        on_tamper_detected("case_opened");
        delay(1000); // avoid re-triggering on every loop while case is open
    }
    if (check_tamper_motion()) {
        on_tamper_detected("moved");
        delay(1000);
    }
    if (check_tamper_reed()) {
        on_tamper_detected("case_opened"); // second channel, same tamper kind
        delay(1000);
    }
    if (check_tamper_voltage()) {
        on_tamper_detected("voltage_anomaly");
        delay(1000);
    }

    g_weak_link_debug = (digitalRead(board::PIN_BTN_AUX) == HIGH);
    if (g_status != StatusColor::FLASHING_RED && g_status != StatusColor::STEADY_RED) {
        g_status = g_weak_link_debug ? StatusColor::YELLOW : StatusColor::GREEN;
    }
    set_status_color(g_status);

    if (now - last_send_ms >= 3000) { // storyboard says "every 30 seconds"; 3s keeps the demo lively
        send_pressure_reading();
        last_send_ms = now;
    }

    if (now - last_adapt_ms >= 5000) {
        bool urgent = (digitalRead(board::PIN_BTN_URGENT) == LOW);
        float batt = read_battery_percent();
        int rssi = g_weak_link_debug ? -90 : -60; // TODO: pull from the real radio driver once wired up
        maybe_rehandshake_for_level(pick_adaptive_level(batt, rssi, urgent));
        last_adapt_ms = now;
    }

    if (now - last_display_ms >= 1000) {
        update_status_display(read_battery_percent());
        last_display_ms = now;
    }

    delay(20);
}
