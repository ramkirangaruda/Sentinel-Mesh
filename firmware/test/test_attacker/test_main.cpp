// Host-side unit tests for src/attacker/attacker_pacer.h (paper task S5 / experiment E7) and, since
// the pacer's whole point is to stay under a real EnergyGate decision, an end-to-end check against
// the actual SlidingLink feature window and the SHIPPED (SIMULATED-trained) decision tree in
// sentinel_proto/energygate_model.h. No ESP32 hardware or PlatformIO required.
//
// Run: see firmware/README.md and tools/run_native_tests.sh, or (one line):
//   g++ -std=gnu++17 -Ilib/sentinel_proto/include -Isrc/attacker test/test_attacker/test_main.cpp
//   lib/sentinel_proto/src/link_window.cpp lib/sentinel_proto/src/energygate.cpp
//   lib/sentinel_proto/src/energy_budget.cpp lib/sentinel_proto/src/gate_policy.cpp
//   -o /tmp/sentinel_attacker_tests && /tmp/sentinel_attacker_tests

#include <cstdio>
#include <cstring>
#include <cassert>

#include "attacker_pacer.h"
#include "sentinel_proto/link_window.h"
#include "sentinel_proto/gate_policy.h"
#include "sentinel_proto/energy_budget.h"

using namespace sentinel;

static int g_pass = 0;
static int g_fail = 0;

#define CHECK(cond) do { \
    if (cond) { g_pass++; } \
    else { g_fail++; std::printf("  FAIL: %s (%s:%d)\n", #cond, __FILE__, __LINE__); } \
} while (0)

#define RUN(name) do { std::printf("-- %s --\n", #name); name(); } while (0)

// ---------------------------------------------------------------------------------
// Pacer unit tests (no field-1 model involved)
// ---------------------------------------------------------------------------------

static void test_pacer_respects_hard_cap_per_window() {
    PacerConfig cfg;
    cfg.window_ms = 5000;
    cfg.max_in_window = 5;
    cfg.max_rate_hz = 10.0f;     // fast enough that only the cap matters
    cfg.min_rate_hz = 10.0f;
    cfg.start_rate_hz = 10.0f;
    AdaptivePacer pacer(cfg);
    uint32_t now = 0;
    int sent = 0;
    for (; now < 5000; now += 50) {
        if (pacer.may_send(now)) { pacer.on_sent(now); sent++; }
    }
    CHECK(sent <= 5);
    CHECK(pacer.in_window(4999) <= 5);
}

static void test_pacer_backs_off_on_challenge_and_recovers() {
    PacerConfig cfg;
    cfg.start_rate_hz = 1.0f;
    cfg.decrease = 0.5f;
    cfg.min_rate_hz = 0.05f;
    cfg.max_rate_hz = 2.0f;
    cfg.hold_ms = 1000;
    cfg.quiet_ms = 2000;
    cfg.increase_hz = 0.1f;
    AdaptivePacer pacer(cfg);
    float before = pacer.rate_hz();
    pacer.on_challenge(1000);
    CHECK(pacer.rate_hz() < before);
    CHECK(pacer.challenges() == 1);
    CHECK(!pacer.may_send(1500));           // inside hold_ms
    CHECK(pacer.may_send(2001) || pacer.may_send(2100));  // hold has lifted
    float after_backoff = pacer.rate_hz();
    // Probe upward after quiet_ms with no further challenge.
    pacer.may_send(2001 + cfg.quiet_ms + 10);
    CHECK(pacer.rate_hz() >= after_backoff);
}

static void test_pacer_never_exceeds_configured_max_rate() {
    PacerConfig cfg;
    cfg.max_rate_hz = 0.8f;
    cfg.start_rate_hz = 0.8f;
    cfg.min_rate_hz = 0.05f;
    cfg.increase_hz = 5.0f;     // would blow past max_rate_hz if not clamped
    cfg.quiet_ms = 100;
    AdaptivePacer pacer(cfg);
    uint32_t now = 0;
    for (int i = 0; i < 50; i++) {
        now += 200;
        pacer.may_send(now);    // ticks the additive-increase probe
    }
    CHECK(pacer.rate_hz() <= cfg.max_rate_hz + 1e-6f);
}

static void test_pacer_max_rate_cannot_exceed_window_cap() {
    // configure() must shrink max_rate_hz so max_rate_hz * window_s <= max_in_window,
    // even if the caller asks for more.
    PacerConfig cfg;
    cfg.window_ms = 5000;
    cfg.max_in_window = 5;
    cfg.max_rate_hz = 100.0f;    // way too fast for the cap
    cfg.start_rate_hz = 100.0f;
    AdaptivePacer pacer(cfg);
    CHECK(pacer.config().max_rate_hz <= 5.0f * 1000.0f / 5000.0f + 1e-6f);
}

static void test_pacer_min_rate_floor() {
    PacerConfig cfg;
    cfg.start_rate_hz = 0.2f;
    cfg.min_rate_hz = 0.1f;
    cfg.decrease = 0.5f;
    cfg.hold_ms = 0;
    AdaptivePacer pacer(cfg);
    for (int i = 0; i < 10; i++) pacer.on_challenge(1000u * (uint32_t)i);
    CHECK(pacer.rate_hz() >= cfg.min_rate_hz - 1e-6f);
}

static void test_fail_in_window_cap_limits_spoof_sends() {
    PacerConfig cfg;
    cfg.window_ms = 5000;
    cfg.max_in_window = 5;
    cfg.max_fail_in_window = 1;   // spoof mode: at most 1 admitted-then-failing HELLO per window
    cfg.max_rate_hz = 10.0f;
    cfg.min_rate_hz = 10.0f;
    cfg.start_rate_hz = 10.0f;
    AdaptivePacer pacer(cfg);
    int sent = 0;
    for (uint32_t now = 0; now < 5000; now += 50) {
        if (pacer.may_send(now)) { pacer.on_sent(now); sent++; }
    }
    CHECK(sent <= 1);
}

// ---------------------------------------------------------------------------------
// End-to-end: pacer output against field-1's real SlidingLink + the shipped tree.
// Mirrors build_gate_features() in src/field_node/main.cpp (link_window.h's
// features() plus a fixed battery_pct -- SIMULATED on the rig, matching the
// field node's -DSENTINEL_NO_BATTERY build).
// ---------------------------------------------------------------------------------

static void test_adaptive_default_config_mostly_spends_against_shipped_tree() {
    SlidingLink link;
    link.reset(0);
    EnergyBudget budget(20.0f, 0.05f);
    GatePolicyConfig gcfg;   // defaults: policy v2, thresholds 0.7 / 0.4 (gate_policy.h)
    PacerConfig pcfg;        // attacker_pacer.h defaults
    AdaptivePacer pacer(pcfg);

    int spend = 0, challenge = 0, drop = 0;
    uint32_t now = 0;
    const uint32_t end = 60000;   // one minute
    while (now < end) {
        link.advance(now);
        if (pacer.may_send(now)) {
            pacer.on_sent(now);
            // A HELLO arriving now is scored on the window as it stood just before this send
            // (mirrors on_hello_frag0: hs_count++ happens, THEN the score is read).
            link.cur().hs_count++;
            float f[ENERGYGATE_NUM_FEATURES];
            link.features(f, /*battery_pct=*/100.0f, now);
            GateInputs in;
            in.prob_real = energygate_score(f);
            in.cookie_echoed = false;
            in.ms_since_last_attempt = NEVER_SEEN;
            GateAction a = decide_admission(DefenseMode::GATE, in, budget, gcfg, now);
            if (a == GateAction::SPEND) { spend++; link.cur().frag_started++; link.cur().frag_completed++; }
            else if (a == GateAction::CHALLENGE) { challenge++; pacer.on_challenge(now); }
            else { drop++; }
        }
        now += 100;
    }
    std::printf("  spend=%d challenge=%d drop=%d final_rate=%.3f/s\n", spend, challenge, drop, pacer.rate_hz());
    // The design intent (attacker_pacer.h's header comment): most HELLOs should be SPENT, not
    // dropped outright, because the pacer keeps hs_per_s under the tree's split.
    CHECK(spend > 0);
    CHECK(spend >= drop);
}

static void test_adaptive_backs_off_when_forced_above_the_cap() {
    // A pacer configured to ignore the cap (as if mis-tuned for a retrained model) should still
    // see CHALLENGEs and reduce its rate -- the AIMD loop is a safety net, not just the cap.
    SlidingLink link;
    link.reset(0);
    EnergyBudget budget(20.0f, 0.05f);
    GatePolicyConfig gcfg;
    PacerConfig pcfg;
    pcfg.max_in_window = 20;       // too permissive for the shipped tree's split (~6)
    pcfg.max_rate_hz = 5.0f;
    pcfg.start_rate_hz = 5.0f;
    pcfg.min_rate_hz = 0.05f;
    pcfg.hold_ms = 200;
    pcfg.quiet_ms = 500;
    AdaptivePacer pacer(pcfg);

    float rate_at_start = pacer.rate_hz();
    uint32_t now = 0;
    int challenges = 0;
    while (now < 10000) {
        link.advance(now);
        if (pacer.may_send(now)) {
            pacer.on_sent(now);
            link.cur().hs_count++;
            float f[ENERGYGATE_NUM_FEATURES];
            link.features(f, 100.0f, now);
            GateInputs in;
            in.prob_real = energygate_score(f);
            GateAction a = decide_admission(DefenseMode::GATE, in, budget, gcfg, now);
            if (a == GateAction::CHALLENGE) { pacer.on_challenge(now); challenges++; }
        }
        now += 50;
    }
    CHECK(challenges > 0);                       // the mis-tuned cap did trigger challenges
    CHECK(pacer.rate_hz() < rate_at_start);        // and the AIMD loop reacted
}

int main() {
    RUN(test_pacer_respects_hard_cap_per_window);
    RUN(test_pacer_backs_off_on_challenge_and_recovers);
    RUN(test_pacer_never_exceeds_configured_max_rate);
    RUN(test_pacer_max_rate_cannot_exceed_window_cap);
    RUN(test_pacer_min_rate_floor);
    RUN(test_fail_in_window_cap_limits_spoof_sends);

    RUN(test_adaptive_default_config_mostly_spends_against_shipped_tree);
    RUN(test_adaptive_backs_off_when_forced_above_the_cap);

    std::printf("\n%d passed, %d failed\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
