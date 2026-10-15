// SentinelMesh attacker firmware -- demo / experiment red-team node.
//
// Phase 6 (paper branch): sends real frames over ESP-NOW at field-1.
//
// Modes, selected over USB serial (`MODE <name>`); a mode keeps running with no
// laptop attached, so the cable can be pulled after the command is sent:
//
//   FLOOD        Forged HELLOs that CLAIM THE GATEWAY'S IDENTITY (an enrolled
//                sender id) with random key/signature bytes, full length. Costs
//                the attacker nothing; costs field-1 the radio reception plus
//                (if admitted) one ML-DSA verification that fails. The loud flood.
//   INSIDER      HELLOs correctly signed with the ATTACKER's own key. field-1 has
//                that key enrolled (a compromised / hostile enrolled peer), so
//                every admitted HELLO forces a FULL handshake: verify + ML-KEM
//                encapsulation + ML-DSA signature + ~19 frames of RESPONSE. The
//                strongest attacker. Rate-limited by this board's own signing cost.
//   SLOW_DRIP    INSIDER at ~1 per minute: under any fixed rate limit, but it still
//                costs a full handshake each time (brief v4 section 6).
//   REPLAY       Captures the first DATA frame from field-1 and re-broadcasts it.
//   IMPERSONATE  HELLOs claiming to be field-1 (which only ever responds) with the
//                attacker's own signature; the gateway flags them.
//   WEAK_LINK    Sends harmless frames with deliberate gaps/jitter (not an attack).
//   OFF          stop.
//
// Other lines: `RATE <per second>` (FLOOD / INSIDER / REPLAY / IMPERSONATE),
// `ECHO on|off` (answer a CHALLENGE by echoing its cookie -- ESP-NOW is a shared
// broadcast medium, so an attacker in range can always hear the cookie; default
// off = a naive attacker), `STATS`.
//
// The attacker never completes a handshake. Its secret key is a committed DEMO
// key (common/demo_keys.h).

#include <Arduino.h>
#include <vector>
#include <cstring>
#include <esp_system.h>
#include <esp_heap_caps.h>

#include "sentinel_proto/packet.h"
#include "sentinel_proto/fragment.h"
#include "sentinel_pqc/pqc_handshake.h"
#include "common/board_config.h"
#include "common/mesh_transport.h"
#include "common/msg_io.h"
#include "common/crypto_task.h"
#include "common/demo_keys.h"

using namespace sentinel;

#ifndef PQC_TASK_STACK_BYTES
#  if SENTINEL_PQC_LEVEL == 1
#    define PQC_TASK_STACK_BYTES 49152
#  else
#    define PQC_TASK_STACK_BYTES 90112
#  endif
#endif

enum class AttackMode { OFF, REPLAY, FLOOD, INSIDER, IMPERSONATE, WEAK_LINK, SLOW_DRIP };
// Boot-time mode: a board powered from a charger has no serial link to type MODE into, and the
// mode is not stored across a power cycle. Build env:attacker_flood / _insider / _slowdrip to
// start attacking at power-up. Plain env:attacker still boots OFF and is driven by MODE lines.
#ifdef SENTINEL_ATTACKER_BOOT_MODE
static AttackMode g_mode = AttackMode::SENTINEL_ATTACKER_BOOT_MODE;
#else
static AttackMode g_mode = AttackMode::OFF;
#endif
static const char* mode_name(AttackMode m) {
    switch (m) {
        case AttackMode::OFF: return "OFF";
        case AttackMode::REPLAY: return "REPLAY";
        case AttackMode::FLOOD: return "FLOOD";
        case AttackMode::INSIDER: return "INSIDER";
        case AttackMode::IMPERSONATE: return "IMPERSONATE";
        case AttackMode::WEAK_LINK: return "WEAK_LINK";
        case AttackMode::SLOW_DRIP: return "SLOW_DRIP";
    }
    return "?";
}

#ifdef SENTINEL_ATTACKER_RATE_HZ
static float g_rate_hz = SENTINEL_ATTACKER_RATE_HZ;   // build-time rate
#else
static float g_rate_hz = 5.0f;             // attempts per second for the rate-driven modes
#endif
constexpr uint32_t SLOW_DRIP_INTERVAL_MS = 60000;
static bool g_echo_cookie = false;

static uint16_t g_epoch = 0xA11C;
static uint32_t g_seq = 1;
static uint32_t g_sent_attempts = 0, g_sent_frames = 0, g_challenges_heard = 0, g_cookie_echoes = 0;

// Buffers (static: several kB).
static uint8_t g_hello[pqc::HELLO_LEN];
static pqc::InitiatorState g_init;
static volatile bool g_hello_valid = false;     // g_hello holds a correctly signed HELLO
static uint16_t g_last_epoch = 0;
static uint32_t g_last_seq = 0;
static uint32_t g_last_tx_ms = 0;

// Captured frame for REPLAY.
static uint8_t g_captured[mesh::MAX_FRAME];
static size_t g_captured_len = 0;

static void send_hello_frames(uint8_t sender_id, const uint8_t* body, size_t len, uint16_t epoch, uint32_t seq) {
    PacketHeader h;
    h.type = MsgType::HELLO;
    h.sender = sender_id;
    h.epoch = epoch;
    h.seq = seq;
    h.time_ms = millis();
    g_last_epoch = epoch;
    g_last_seq = seq;
    if (send_message(h, body, len) > 0) g_sent_frames += (len + MAX_FRAGMENT_PAYLOAD - 1) / MAX_FRAGMENT_PAYLOAD;
    g_sent_attempts++;
}

// ---------------------------------------------------------------------
// Modes
// ---------------------------------------------------------------------

static void tick_flood(uint32_t now) {
    uint32_t interval = static_cast<uint32_t>(1000.0f / g_rate_hz);
    if (now - g_last_tx_ms < interval) return;
    g_last_tx_ms = now;
    esp_fill_random(g_hello, sizeof(g_hello));                 // forged: random nonce / key / signature
    memset(g_hello, 0, pqc::COOKIE_BYTES);                      // no cookie
    send_hello_frames(static_cast<uint8_t>(NodeId::GATEWAY), g_hello, sizeof(g_hello), g_epoch++, g_seq++);
}

static void job_make_signed_hello(void*) {
    // Valid HELLO under the attacker's OWN enrolled key, addressed to field-1.
    pqc::Hooks none;
    if (pqc::initiator_make_hello(g_init, static_cast<uint8_t>(NodeId::ATTACKER), static_cast<uint8_t>(NodeId::FIELD_1),
                                  demo_keys::SIG_SK_ATTACKER, none, g_hello) != pqc::Result::OK) {
        g_hello_valid = false;
        return;
    }
    g_hello_valid = true;
    send_hello_frames(static_cast<uint8_t>(NodeId::ATTACKER), g_hello, sizeof(g_hello), g_epoch++, g_seq++);
}

static void tick_insider(uint32_t now, uint32_t interval_ms) {
    if (now - g_last_tx_ms < interval_ms || crypto_task_busy()) return;
    g_last_tx_ms = now;
    crypto_task_submit(job_make_signed_hello, nullptr);
}

static void tick_replay(uint32_t now) {
    if (g_captured_len == 0) return;      // nothing captured yet: listen
    uint32_t interval = static_cast<uint32_t>(1000.0f / g_rate_hz);
    if (now - g_last_tx_ms < interval) return;
    g_last_tx_ms = now;
    if (mesh::broadcast(g_captured, g_captured_len)) { g_sent_frames++; g_sent_attempts++; }
}

static void tick_impersonate(uint32_t now) {
    uint32_t interval = static_cast<uint32_t>(1000.0f / g_rate_hz);
    if (now - g_last_tx_ms < interval) return;
    g_last_tx_ms = now;
    esp_fill_random(g_hello, sizeof(g_hello));
    memset(g_hello, 0, pqc::COOKIE_BYTES);
    send_hello_frames(static_cast<uint8_t>(NodeId::FIELD_1), g_hello, sizeof(g_hello), g_epoch++, g_seq++);
}

static void tick_weak_link(uint32_t now) {
    static uint32_t next = 0;
    if (now < next) return;
    next = now + 1000 + random(0, 400);                 // jitter
    if (random(0, 5) == 0) return;                      // ~1 in 5 dropped
    uint8_t junk[8];
    esp_fill_random(junk, sizeof(junk));
    PacketHeader h;
    h.type = MsgType::DATA;
    h.sender = static_cast<uint8_t>(NodeId::ATTACKER);
    h.epoch = g_epoch;
    h.seq = g_seq++;
    h.time_ms = now;
    send_message(h, junk, sizeof(junk));
}

// ---------------------------------------------------------------------
// Receive path: capture for REPLAY, hear CHALLENGEs for ECHO
// ---------------------------------------------------------------------

static void on_frame(const mesh::Frame& fr) {
    PacketHeader hdr;
    if (!PacketHeader::deserialize(fr.data, fr.len, hdr)) return;

    if (g_mode == AttackMode::REPLAY && g_captured_len == 0 &&
        hdr.type == MsgType::DATA && hdr.sender == static_cast<uint8_t>(NodeId::FIELD_1)) {
        memcpy(g_captured, fr.data, fr.len);
        g_captured_len = fr.len;
        Serial.printf("LOG captured a DATA frame from field-1 (%u bytes) for replay\n", (unsigned)fr.len);
        return;
    }

    if (hdr.type == MsgType::CHALLENGE && hdr.sender == static_cast<uint8_t>(NodeId::FIELD_1) &&
        (g_mode == AttackMode::INSIDER || g_mode == AttackMode::SLOW_DRIP) &&
        hdr.epoch == g_last_epoch && hdr.seq == g_last_seq) {
        g_challenges_heard++;
        if (g_echo_cookie && g_hello_valid && !crypto_task_busy() && hdr.frag_n == 1 &&
            fr.len - HEADER_SIZE >= pqc::COOKIE_BYTES) {
            pqc::hello_set_cookie(g_hello, fr.data + HEADER_SIZE);
            send_hello_frames(static_cast<uint8_t>(NodeId::ATTACKER), g_hello, sizeof(g_hello), g_epoch++, g_seq++);
            g_cookie_echoes++;
        }
    }
}

// ---------------------------------------------------------------------
// Serial command intake
// ---------------------------------------------------------------------

static void handle_command(const String& cmd) {
    if (cmd.startsWith("MODE ")) {
        String m = cmd.substring(5);
        m.trim();
        AttackMode nm;
        if (m == "OFF") nm = AttackMode::OFF;
        else if (m == "REPLAY") nm = AttackMode::REPLAY;
        else if (m == "FLOOD") nm = AttackMode::FLOOD;
        else if (m == "INSIDER") nm = AttackMode::INSIDER;
        else if (m == "IMPERSONATE") nm = AttackMode::IMPERSONATE;
        else if (m == "WEAK_LINK") nm = AttackMode::WEAK_LINK;
        else if (m == "SLOW_DRIP") nm = AttackMode::SLOW_DRIP;
        else { Serial.print("LOG unknown mode: "); Serial.println(m); return; }
        g_mode = nm;
        if (nm == AttackMode::REPLAY) g_captured_len = 0;
        // SLOW_DRIP fires its first attempt immediately instead of after a minute.
        g_last_tx_ms = (nm == AttackMode::SLOW_DRIP) ? millis() - SLOW_DRIP_INTERVAL_MS : 0;
        Serial.printf("LOG mode set to MODE %s\n", mode_name(g_mode));
    } else if (cmd.startsWith("RATE ")) {
        float r = cmd.substring(5).toFloat();
        if (r > 0.0f && r <= 200.0f) { g_rate_hz = r; Serial.printf("LOG rate %.2f /s\n", g_rate_hz); }
    } else if (cmd == "ECHO on" || cmd == "ECHO off") {
        g_echo_cookie = (cmd == "ECHO on");
        Serial.printf("LOG cookie echo %s\n", g_echo_cookie ? "on" : "off");
    } else if (cmd == "STATS") {
        Serial.printf("LOG attacker stats mode=%s attempts=%lu frames=%lu challenges_heard=%lu cookie_echoes=%lu rate=%.2f\n",
                      mode_name(g_mode), (unsigned long)g_sent_attempts, (unsigned long)g_sent_frames,
                      (unsigned long)g_challenges_heard, (unsigned long)g_cookie_echoes, g_rate_hz);
    }
    // Other lines (LABEL, DEFENSE, HS ...) belong to other boards: ignore.
}

// ---------------------------------------------------------------------
// Arduino entry points
// ---------------------------------------------------------------------

void setup() {
    Serial.begin(board::CONSOLE_SERIAL_BAUD);
    randomSeed(esp_random());
    bool crypto_ok = crypto_task_start(PQC_TASK_STACK_BYTES, 0);   // before Wi-Fi fragments the heap
    bool mesh_ok = mesh::init();
    Serial.printf("LOG attacker boot complete (%s+%s) crypto_task=%s mesh=%s. Commands: MODE FLOOD|INSIDER|SLOW_DRIP|REPLAY|IMPERSONATE|WEAK_LINK|OFF, RATE <hz>, ECHO on|off, STATS\n",
                  SM_PQC_KEM_NAME, SM_PQC_SIG_NAME, crypto_ok ? "ok" : "FAILED", mesh_ok ? "ok" : "FAILED");
    if (g_mode == AttackMode::SLOW_DRIP) g_last_tx_ms = millis() - SLOW_DRIP_INTERVAL_MS;   // first attempt at once
    if (g_mode != AttackMode::OFF)
        Serial.printf("LOG boot mode: MODE %s at %.2f /s (build-time default)\n", mode_name(g_mode), g_rate_hz);
}

void loop() {
    while (Serial.available()) {
        String line = Serial.readStringUntil('\n');
        line.trim();
        if (line.length() > 0) handle_command(line);
    }

    int handled = 0;
    mesh::Frame fr;
    while (handled < 16 && mesh::poll(fr)) { on_frame(fr); handled++; }

    uint32_t now = millis();
    switch (g_mode) {
        case AttackMode::FLOOD: tick_flood(now); break;
        case AttackMode::INSIDER: tick_insider(now, static_cast<uint32_t>(1000.0f / g_rate_hz)); break;
        case AttackMode::SLOW_DRIP: tick_insider(now, SLOW_DRIP_INTERVAL_MS); break;
        case AttackMode::REPLAY: tick_replay(now); break;
        case AttackMode::IMPERSONATE: tick_impersonate(now); break;
        case AttackMode::WEAK_LINK: tick_weak_link(now); break;
        case AttackMode::OFF: break;
    }
    delay(handled ? 0 : 1);
}
