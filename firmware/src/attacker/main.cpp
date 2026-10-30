// SentinelMesh attacker firmware -- demo / experiment red-team node.
//
// Phase 6 (paper branch): sends real frames over ESP-NOW at field-1.
//
// Modes, selected over USB serial (`MODE <name>`); a mode keeps running with no
// laptop attached, so the cable can be pulled after the command is sent:
//
//   FLOOD        Forged HELLOs that CLAIM THE GATEWAY'S IDENTITY (an enrolled
//                sender id) with random key/signature bytes, full length. Costs
//                the attacker nothing; costs field-1 only the radio reception plus a CHEAP
//                rejection -- ML-DSA verify rejects a malformed signature while unpacking it,
//                before the expensive maths (paper/CONTEXT_2026-10-24.md "Finding 2": ~1.7 ms,
//                not a full verification). Loud, but barely moves field-1's power.
//   FORGE        (paper task S5/S-forge) Builds ONE well-formed HELLO once, signed for real by
//                the attacker's own enrolled key, then RESENDS those exact bytes under the
//                GATEWAY's claimed identity with a fresh (epoch, seq) each time. A correctly
//                encoded signature passes the cheap unpacking checks FLOOD fails, so field-1 runs
//                the FULL verification (measured in E2: ~26.2 ms, 3.2 mJ above idle) and only
//                fails at the very end, because the key and transcript don't match the claimed
//                sender. One signing op on the attacker forces the full check every resend: the
//                energy asymmetry the paper's claim C2 needs. See forge_template.h.
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
//   ADAPTIVE     (E7) INSIDER that knows EnergyGate's features. Valid signatures (hs_fail stays 0), a
//                fresh sequence number per HELLO (dup_pct stays 0), paced by attacker_pacer.h to stay
//                under the trained tree's hs_per_s split; backs off on a CHALLENGE and probes back up.
//                ECHO on additionally answers a CHALLENGE with the cookie.
//   ADAPTIVE_SPOOF  As ADAPTIVE but forged HELLOs claiming the gateway's id (no key needed): each
//                admitted one fails verification, so the pacer also caps attempts per window (hs_fail <= 1).
//   WEAK_LINK    Sends harmless frames with deliberate gaps/jitter (not an attack).
//   OFF          stop.
//
// Other lines: `RATE <per second>` (FLOOD / INSIDER / REPLAY / IMPERSONATE),
// `ECHO on|same|off` (answer a CHALLENGE by echoing its cookie; `same` resends under the challenged (epoch, seq) -- ESP-NOW is a shared
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
#include "attacker_pacer.h"
#include "forge_template.h"

using namespace sentinel;

#ifndef PQC_TASK_STACK_BYTES
#  if SENTINEL_PQC_LEVEL == 1
#    define PQC_TASK_STACK_BYTES 49152
#  else
#    define PQC_TASK_STACK_BYTES 90112
#  endif
#endif

enum class AttackMode { OFF, REPLAY, FLOOD, INSIDER, IMPERSONATE, WEAK_LINK, SLOW_DRIP, ADAPTIVE, ADAPTIVE_SPOOF, FORGE };
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
        case AttackMode::ADAPTIVE: return "ADAPTIVE";
        case AttackMode::ADAPTIVE_SPOOF: return "ADAPTIVE_SPOOF";
        case AttackMode::FORGE: return "FORGE";
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
static bool g_echo_same_seq = false;            // ECHO same: resend under the challenged (epoch, seq), which a bound cookie accepts
static AdaptivePacer g_pacer;                   // ADAPTIVE / ADAPTIVE_SPOOF pacing (attacker_pacer.h)
static CachedTemplate<pqc::HELLO_LEN> g_forge;  // FORGE's one-signed, many-resent HELLO (forge_template.h)

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

static void job_make_forge_template(void*) {
    // Signs ONE HELLO for real, the same way job_make_signed_hello does (attacker's own enrolled
    // key, addressed to field-1) -- that produces a correctly ENCODED ML-DSA signature, which is
    // all FORGE needs: it is resent under the GATEWAY's claimed identity, so it will never verify
    // (wrong key, wrong transcript), but it is well-formed enough to reach the full verification
    // instead of being rejected during signature unpacking like FLOOD's random bytes.
    if (g_forge.ready()) return;   // already built this entry into MODE FORGE
    uint8_t tmp[pqc::HELLO_LEN];
    pqc::Hooks none;
    if (pqc::initiator_make_hello(g_init, static_cast<uint8_t>(NodeId::ATTACKER), static_cast<uint8_t>(NodeId::FIELD_1),
                                  demo_keys::SIG_SK_ATTACKER, none, tmp) != pqc::Result::OK) {
        return;
    }
    memset(tmp, 0, pqc::COOKIE_BYTES);   // no cookie yet: outside the signed transcript, same as tick_flood
    g_forge.set(tmp, sizeof(tmp));
    Serial.println("LOG forge template ready (one signing op; resent under the gateway's claimed id)");
}

// FORGE: resend the cached, once-signed template under the GATEWAY's identity with a fresh
// (epoch, seq) each time. No crypto work here -- that is the whole point (forge_template.h).
static void tick_forge(uint32_t now) {
    if (!g_forge.ready()) {
        // MODE FORGE's one crypto_task_submit() (handle_command) can be dropped if the crypto
        // task was already busy with another job at that moment -- it is never queued, and
        // nothing would otherwise retry it, leaving the template permanently unbuilt. Retry here
        // every tick until it is accepted; job_make_forge_template() itself is a no-op once
        // g_forge.ready() (set the moment a retry succeeds), so this never double-signs.
        if (!crypto_task_busy()) crypto_task_submit(job_make_forge_template, nullptr);
        return;
    }
    uint32_t interval = static_cast<uint32_t>(1000.0f / g_rate_hz);
    if (now - g_last_tx_ms < interval) return;
    g_last_tx_ms = now;
    send_hello_frames(static_cast<uint8_t>(NodeId::GATEWAY), g_forge.data(), g_forge.size(), g_epoch++, g_seq++);
}

// ADAPTIVE: a validly signed HELLO under the attacker's enrolled key, sent only when the pacer allows
// (attacker_pacer.h: stays under the shipped tree's hs_per_s split, backs off on a heard CHALLENGE).
static void tick_adaptive(uint32_t now) {
    if (crypto_task_busy() || !g_pacer.may_send(now)) return;
    g_pacer.on_sent(now);
    g_last_tx_ms = now;
    crypto_task_submit(job_make_signed_hello, nullptr);
}

// ADAPTIVE_SPOOF: forged HELLO claiming the gateway's id (no enrolled key needed), gated the same way;
// the pacer's max_fail_in_window additionally bounds how many can be admitted-then-failing per window.
static void tick_adaptive_spoof(uint32_t now) {
    if (!g_pacer.may_send(now)) return;
    g_pacer.on_sent(now);
    g_last_tx_ms = now;
    esp_fill_random(g_hello, sizeof(g_hello));
    memset(g_hello, 0, pqc::COOKIE_BYTES);
    send_hello_frames(static_cast<uint8_t>(NodeId::GATEWAY), g_hello, sizeof(g_hello), g_epoch++, g_seq++);
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
        (g_mode == AttackMode::INSIDER || g_mode == AttackMode::SLOW_DRIP || g_mode == AttackMode::ADAPTIVE ||
         g_mode == AttackMode::ADAPTIVE_SPOOF || g_mode == AttackMode::FORGE) &&
        hdr.epoch == g_last_epoch && hdr.seq == g_last_seq) {
        g_challenges_heard++;
        if (g_mode == AttackMode::ADAPTIVE || g_mode == AttackMode::ADAPTIVE_SPOOF) {
            g_pacer.on_challenge(millis());   // back off: the score fell under the gate's spend threshold
        }
        if (g_echo_cookie && hdr.frag_n == 1 && fr.len - HEADER_SIZE >= pqc::COOKIE_BYTES) {
            if (g_mode == AttackMode::FORGE && g_forge.ready()) {
                // The cookie sits outside the signed transcript (pqc_handshake.h), so patching it
                // into the already-cached template does not invalidate the one real signature.
                pqc::hello_set_cookie(g_forge.mutable_data(), fr.data + HEADER_SIZE);
                send_hello_frames(static_cast<uint8_t>(NodeId::GATEWAY), g_forge.data(), g_forge.size(),
                                 g_echo_same_seq ? hdr.epoch : g_epoch++, g_echo_same_seq ? hdr.seq : g_seq++);
                g_cookie_echoes++;
            } else if (g_hello_valid && !crypto_task_busy()) {
                pqc::hello_set_cookie(g_hello, fr.data + HEADER_SIZE);
                send_hello_frames(static_cast<uint8_t>(NodeId::ATTACKER), g_hello, sizeof(g_hello),
                                 g_echo_same_seq ? hdr.epoch : g_epoch++, g_echo_same_seq ? hdr.seq : g_seq++);
                g_cookie_echoes++;
            }
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
        else if (m == "ADAPTIVE") nm = AttackMode::ADAPTIVE;
        else if (m == "ADAPTIVE_SPOOF") nm = AttackMode::ADAPTIVE_SPOOF;
        else if (m == "FORGE") nm = AttackMode::FORGE;
        else { Serial.print("LOG unknown mode: "); Serial.println(m); return; }
        g_mode = nm;
        if (nm == AttackMode::REPLAY) g_captured_len = 0;
        if (nm == AttackMode::ADAPTIVE || nm == AttackMode::ADAPTIVE_SPOOF) g_pacer.reset(millis());
        // Entering FORGE (from any other mode, including re-entering FORGE) always starts from a
        // fresh, not-yet-signed template; leaving it (MODE OFF or any other mode) clears readiness
        // too, so a later re-entry signs again rather than resending a stale cached HELLO.
        g_forge.clear();
        if (nm == AttackMode::FORGE) crypto_task_submit(job_make_forge_template, nullptr);
        // SLOW_DRIP fires its first attempt immediately instead of after a minute.
        g_last_tx_ms = (nm == AttackMode::SLOW_DRIP) ? millis() - SLOW_DRIP_INTERVAL_MS : 0;
        Serial.printf("LOG mode set to MODE %s\n", mode_name(g_mode));
    } else if (cmd.startsWith("RATE ")) {
        float r = cmd.substring(5).toFloat();
        if (r > 0.0f && r <= 200.0f) { g_rate_hz = r; Serial.printf("LOG rate %.2f /s\n", g_rate_hz); }
    } else if (cmd == "ECHO on" || cmd == "ECHO same" || cmd == "ECHO off") {
        g_echo_cookie = (cmd != "ECHO off");
        g_echo_same_seq = (cmd == "ECHO same");
        Serial.printf("LOG cookie echo %s\n", g_echo_same_seq ? "same" : (g_echo_cookie ? "on" : "off"));
    } else if (cmd == "STATS") {
        Serial.printf("LOG attacker stats mode=%s attempts=%lu frames=%lu challenges_heard=%lu cookie_echoes=%lu "
                      "rate=%.2f pacer_rate=%.3f pacer_challenges=%lu forge_ready=%s\n",
                      mode_name(g_mode), (unsigned long)g_sent_attempts, (unsigned long)g_sent_frames,
                      (unsigned long)g_challenges_heard, (unsigned long)g_cookie_echoes, g_rate_hz,
                      g_pacer.rate_hz(), (unsigned long)g_pacer.challenges(), g_forge.ready() ? "yes" : "no");
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
    Serial.printf("LOG attacker boot complete (%s+%s) crypto_task=%s mesh=%s. Commands: "
                  "MODE FLOOD|FORGE|INSIDER|SLOW_DRIP|ADAPTIVE|ADAPTIVE_SPOOF|REPLAY|IMPERSONATE|WEAK_LINK|OFF, "
                  "RATE <hz>, ECHO on|same|off, STATS\n",
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
        case AttackMode::FORGE: tick_forge(now); break;
        case AttackMode::INSIDER: tick_insider(now, static_cast<uint32_t>(1000.0f / g_rate_hz)); break;
        case AttackMode::SLOW_DRIP: tick_insider(now, SLOW_DRIP_INTERVAL_MS); break;
        case AttackMode::ADAPTIVE: tick_adaptive(now); break;
        case AttackMode::ADAPTIVE_SPOOF: tick_adaptive_spoof(now); break;
        case AttackMode::REPLAY: tick_replay(now); break;
        case AttackMode::IMPERSONATE: tick_impersonate(now); break;
        case AttackMode::WEAK_LINK: tick_weak_link(now); break;
        case AttackMode::OFF: break;
    }
    delay(handled ? 0 : 1);
}
