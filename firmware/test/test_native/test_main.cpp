// Host-side unit tests for sentinel_proto: packet header, fragmentation/
// reassembly, and replay window. No ESP32 hardware or PlatformIO required —
// this is plain, portable C++ compiled directly against the lib sources.
//
// Run: see firmware/README.md ("Host-side unit tests"), or:
//   g++ -std=gnu++17 -I../../lib/sentinel_proto/include
//       test_main.cpp ../../lib/sentinel_proto/src/*.cpp -o /tmp/sentinel_tests
//   /tmp/sentinel_tests
//
// Intentionally dependency-free (no test framework) so it builds anywhere
// a C++17 compiler is available.

#include <cstdio>
#include <cstring>
#include <cassert>
#include <vector>
#include <string>

#include "sentinel_proto/packet.h"
#include "sentinel_proto/fragment.h"
#include "sentinel_proto/replay.h"
#include "sentinel_proto/field_model.h"
#include "sentinel_proto/cookie.h"
#include "sentinel_proto/energy_budget.h"
#include "sentinel_proto/energygate.h"
#include "sentinel_proto/gate_policy.h"
#include "sentinel_proto/gate_msgs.h"

using namespace sentinel;

static int g_pass = 0;
static int g_fail = 0;

#define CHECK(cond) do { \
    if (cond) { g_pass++; } \
    else { g_fail++; std::printf("  FAIL: %s (%s:%d)\n", #cond, __FILE__, __LINE__); } \
} while (0)

#define RUN(name) do { std::printf("-- %s --\n", #name); name(); } while (0)

// ---------------------------------------------------------------------
// PacketHeader
// ---------------------------------------------------------------------

static void test_header_roundtrip_basic() {
    PacketHeader h;
    h.version = PROTO_VERSION;
    h.type = MsgType::DATA;
    h.sender = static_cast<uint8_t>(NodeId::FIELD_1);
    h.epoch = 0xDEADBEEF;
    h.seq = 4242;
    h.time_ms = 123456789;
    h.prio = 7;
    h.frag_i = 0;
    h.frag_n = 1;

    uint8_t buf[HEADER_SIZE];
    size_t n = h.serialize(buf, sizeof(buf));
    CHECK(n == HEADER_SIZE);

    PacketHeader parsed;
    bool ok = PacketHeader::deserialize(buf, sizeof(buf), parsed);
    CHECK(ok);
    CHECK(parsed == h);
}

static void test_header_all_msg_types_roundtrip() {
    MsgType types[] = {MsgType::HELLO, MsgType::RESPONSE, MsgType::CONFIRM,
                        MsgType::DATA, MsgType::ACK, MsgType::REKEY};
    for (MsgType t : types) {
        PacketHeader h;
        h.type = t;
        h.sender = 9;
        h.epoch = 1;
        h.seq = 1;
        h.time_ms = 1;
        h.frag_n = 1;
        uint8_t buf[HEADER_SIZE];
        h.serialize(buf, sizeof(buf));
        PacketHeader parsed;
        CHECK(PacketHeader::deserialize(buf, sizeof(buf), parsed));
        CHECK(parsed.type == t);
    }
}

static void test_header_rejects_short_buffer() {
    PacketHeader h;
    uint8_t buf[HEADER_SIZE];
    CHECK(h.serialize(buf, HEADER_SIZE - 1) == 0);

    PacketHeader parsed;
    CHECK(!PacketHeader::deserialize(buf, HEADER_SIZE - 1, parsed));
}

static void test_header_rejects_bad_version() {
    PacketHeader h;
    h.version = PROTO_VERSION;
    h.frag_n = 1;
    uint8_t buf[HEADER_SIZE];
    h.serialize(buf, sizeof(buf));
    buf[0] = (0xF << 4) | static_cast<uint8_t>(MsgType::DATA); // bogus version 15
    PacketHeader parsed;
    CHECK(!PacketHeader::deserialize(buf, sizeof(buf), parsed));
}

static void test_header_rejects_bad_msg_type() {
    PacketHeader h;
    h.frag_n = 1;
    uint8_t buf[HEADER_SIZE];
    h.serialize(buf, sizeof(buf));
    buf[0] = (PROTO_VERSION << 4) | 0x0F; // bogus type nibble, not in enum
    PacketHeader parsed;
    CHECK(!PacketHeader::deserialize(buf, sizeof(buf), parsed));
}

static void test_header_rejects_frag_i_out_of_range() {
    PacketHeader h;
    h.frag_n = 3;
    h.frag_i = 5; // >= frag_n, invalid
    uint8_t buf[HEADER_SIZE];
    h.serialize(buf, sizeof(buf));
    PacketHeader parsed;
    CHECK(!PacketHeader::deserialize(buf, sizeof(buf), parsed));
}

// ---------------------------------------------------------------------
// Fragmentation / reassembly
// ---------------------------------------------------------------------

static std::vector<uint8_t> make_payload(size_t n, uint8_t seed = 0) {
    std::vector<uint8_t> v(n);
    for (size_t i = 0; i < n; ++i) v[i] = static_cast<uint8_t>((seed + i) & 0xFF);
    return v;
}

static void test_fragment_small_payload_single_fragment() {
    PacketHeader tmpl;
    tmpl.sender = 1; tmpl.epoch = 1; tmpl.seq = 10; tmpl.type = MsgType::DATA;
    auto payload = make_payload(50);

    auto frags = Fragmenter::split(tmpl, payload.data(), payload.size(), MAX_FRAGMENT_PAYLOAD);
    CHECK(frags.size() == 1);
    CHECK(frags[0].size() == HEADER_SIZE + 50);
}

static void test_fragment_large_payload_multi_fragment_and_reassembles() {
    PacketHeader tmpl;
    tmpl.sender = 1; tmpl.epoch = 7; tmpl.seq = 99; tmpl.type = MsgType::DATA;
    const size_t mtu = 32;
    auto payload = make_payload(100, /*seed=*/5); // -> 4 fragments (32*3 + 4)

    auto frags = Fragmenter::split(tmpl, payload.data(), payload.size(), mtu);
    CHECK(frags.size() == 4);

    Reassembler r;
    std::vector<uint8_t> out;
    bool completed = false;
    // Feed in order; only the last one should report completion.
    for (size_t i = 0; i < frags.size(); ++i) {
        PacketHeader hdr;
        CHECK(PacketHeader::deserialize(frags[i].data(), frags[i].size(), hdr));
        const uint8_t* p = frags[i].data() + HEADER_SIZE;
        size_t plen = frags[i].size() - HEADER_SIZE;
        bool done = r.feed(hdr, p, plen, /*now_ms=*/1000 + i, out);
        if (i + 1 < frags.size()) {
            CHECK(!done);
        } else {
            CHECK(done);
            completed = true;
        }
    }
    CHECK(completed);
    CHECK(out.size() == payload.size());
    CHECK(std::memcmp(out.data(), payload.data(), payload.size()) == 0);
}

static void test_fragment_out_of_order_reassembles() {
    PacketHeader tmpl;
    tmpl.sender = 2; tmpl.epoch = 1; tmpl.seq = 1; tmpl.type = MsgType::DATA;
    const size_t mtu = 10;
    auto payload = make_payload(35, 1); // 4 fragments
    auto frags = Fragmenter::split(tmpl, payload.data(), payload.size(), mtu);
    CHECK(frags.size() == 4);

    // Feed in shuffled order: 2, 0, 3, 1
    size_t order[] = {2, 0, 3, 1};
    Reassembler r;
    std::vector<uint8_t> out;
    bool done = false;
    for (size_t idx : order) {
        PacketHeader hdr;
        PacketHeader::deserialize(frags[idx].data(), frags[idx].size(), hdr);
        const uint8_t* p = frags[idx].data() + HEADER_SIZE;
        size_t plen = frags[idx].size() - HEADER_SIZE;
        done = r.feed(hdr, p, plen, 0, out);
    }
    CHECK(done);
    CHECK(out.size() == payload.size());
    CHECK(std::memcmp(out.data(), payload.data(), payload.size()) == 0);
}

static void test_fragment_duplicate_fragment_ignored() {
    PacketHeader tmpl;
    tmpl.sender = 3; tmpl.epoch = 1; tmpl.seq = 5; tmpl.type = MsgType::DATA;
    auto payload = make_payload(20, 2);
    auto frags = Fragmenter::split(tmpl, payload.data(), payload.size(), 10); // 2 fragments

    Reassembler r;
    std::vector<uint8_t> out;
    PacketHeader h0, h1;
    PacketHeader::deserialize(frags[0].data(), frags[0].size(), h0);
    PacketHeader::deserialize(frags[1].data(), frags[1].size(), h1);

    // Feed fragment 0 twice (retransmit), then fragment 1.
    CHECK(!r.feed(h0, frags[0].data() + HEADER_SIZE, frags[0].size() - HEADER_SIZE, 0, out));
    CHECK(!r.feed(h0, frags[0].data() + HEADER_SIZE, frags[0].size() - HEADER_SIZE, 1, out));
    CHECK(r.active_streams() == 1);
    CHECK(r.feed(h1, frags[1].data() + HEADER_SIZE, frags[1].size() - HEADER_SIZE, 2, out));
    CHECK(out.size() == payload.size());
}

static void test_fragment_timeout_expires_incomplete_stream() {
    PacketHeader tmpl;
    tmpl.sender = 4; tmpl.epoch = 1; tmpl.seq = 1; tmpl.type = MsgType::DATA;
    auto payload = make_payload(30, 3);
    auto frags = Fragmenter::split(tmpl, payload.data(), payload.size(), 10); // 3 fragments
    CHECK(frags.size() == 3);

    Reassembler r(/*timeout_ms=*/1000);
    std::vector<uint8_t> out;
    PacketHeader h0;
    PacketHeader::deserialize(frags[0].data(), frags[0].size(), h0);
    r.feed(h0, frags[0].data() + HEADER_SIZE, frags[0].size() - HEADER_SIZE, /*now_ms=*/0, out);
    CHECK(r.active_streams() == 1);

    size_t evicted = r.expire(/*now_ms=*/500); // within timeout
    CHECK(evicted == 0);
    CHECK(r.active_streams() == 1);

    evicted = r.expire(/*now_ms=*/2000); // past timeout
    CHECK(evicted == 1);
    CHECK(r.active_streams() == 0);
}

static void test_fragment_stream_cap_rejects_new_streams_when_full() {
    Reassembler r(/*timeout_ms=*/100000, /*max_streams=*/2);
    std::vector<uint8_t> out;

    for (uint16_t seq = 0; seq < 2; ++seq) {
        PacketHeader h;
        h.sender = 1; h.epoch = 1; h.seq = seq; h.frag_i = 0; h.frag_n = 2;
        uint8_t p[1] = {0};
        r.feed(h, p, 1, 0, out);
    }
    CHECK(r.active_streams() == 2);

    // A third distinct stream should be refused (table full).
    PacketHeader h3;
    h3.sender = 1; h3.epoch = 1; h3.seq = 99; h3.frag_i = 0; h3.frag_n = 2;
    uint8_t p[1] = {0};
    bool completed = r.feed(h3, p, 1, 0, out);
    CHECK(!completed);
    CHECK(r.active_streams() == 2);
}

// ---------------------------------------------------------------------
// Replay window
// ---------------------------------------------------------------------

static void test_replay_first_packet_accepted() {
    ReplayFilter f;
    CHECK(f.check(1, 10, 1000, 1000) == ReplayFilter::Result::ACCEPT);
}

static void test_replay_monotonic_sequence_all_accepted() {
    ReplayFilter f;
    for (uint16_t s = 0; s < 100; ++s) {
        CHECK(f.check(1, s, s * 10, s * 10) == ReplayFilter::Result::ACCEPT);
    }
}

static void test_replay_exact_duplicate_rejected_as_duplicate() {
    ReplayFilter f;
    CHECK(f.check(1, 5, 100, 100) == ReplayFilter::Result::ACCEPT);
    CHECK(f.check(1, 5, 100, 100) == ReplayFilter::Result::DUPLICATE);
}

static void test_replay_old_seq_outside_window_rejected() {
    ReplayFilter f;
    CHECK(f.check(1, 100, 0, 0) == ReplayFilter::Result::ACCEPT);
    // 70 back is outside the 64-bit window.
    CHECK(f.check(1, 30, 0, 0) == ReplayFilter::Result::REPLAY_REJECTED);
}

static void test_replay_in_window_out_of_order_accepted_once() {
    ReplayFilter f;
    CHECK(f.check(1, 100, 0, 0) == ReplayFilter::Result::ACCEPT);
    CHECK(f.check(1, 98, 0, 0) == ReplayFilter::Result::ACCEPT);  // gap, still in window
    CHECK(f.check(1, 99, 0, 0) == ReplayFilter::Result::ACCEPT);  // fills gap
    CHECK(f.check(1, 99, 0, 0) == ReplayFilter::Result::DUPLICATE); // now a dup
}

static void test_replay_captured_and_replayed_packet_rejected() {
    ReplayFilter f;
    // Attacker captures seq=50 at time_ms=5000, then replays it later once
    // the receiver's window has moved well past it.
    CHECK(f.check(1, 50, 5000, 5000) == ReplayFilter::Result::ACCEPT);
    for (uint16_t s = 51; s <= 130; ++s) {
        f.check(1, s, 5000 + (s - 50) * 10, 5000 + (s - 50) * 10);
    }
    // Replay the captured seq=50 packet (same time_ms, now stale/out of window).
    CHECK(f.check(1, 50, 5000, 5000 + 80 * 10) == ReplayFilter::Result::REPLAY_REJECTED);
}

static void test_replay_stale_timestamp_rejected_even_with_fresh_seq() {
    ReplayFilter f(/*freshness_threshold_ms=*/2000);
    CHECK(f.check(1, 1, 0, 0) == ReplayFilter::Result::ACCEPT);
    // seq=2 is a brand-new, in-order seq, but its timestamp is wildly off
    // from the receiver's session clock -> should be rejected on freshness
    // before the window even matters.
    CHECK(f.check(1, 2, 0, 10000) == ReplayFilter::Result::STALE_TIMESTAMP);
}

static void test_replay_reset_clears_peer_state() {
    ReplayFilter f;
    CHECK(f.check(1, 10, 0, 0) == ReplayFilter::Result::ACCEPT);
    CHECK(f.check(1, 10, 0, 0) == ReplayFilter::Result::DUPLICATE);
    f.reset(1);
    // After reset (e.g. re-handshake / new epoch), same seq is accepted again.
    CHECK(f.check(1, 10, 0, 0) == ReplayFilter::Result::ACCEPT);
}

static void test_replay_peers_are_independent() {
    ReplayFilter f;
    CHECK(f.check(1, 10, 0, 0) == ReplayFilter::Result::ACCEPT);
    // Same seq from a different peer is unrelated state -> accepted.
    CHECK(f.check(2, 10, 0, 0) == ReplayFilter::Result::ACCEPT);
}

// ---------------------------------------------------------------------
// Rule-based field model (stand-in for ml/export/field_model.h)
// ---------------------------------------------------------------------
// Feature order: hs_per_s, hs_fail, replay_rej, auth_fail, stale,
// frag_timeout, rssi_mean, rssi_var, loss_pct, jitter_ms.

static void test_field_model_normal_window() {
    float f[FIELD_MODEL_NUM_FEATURES] = {0.2f, 0, 0, 0, 0, 0, -55.0f, 2.0f, 0.5f, 3.0f};
    CHECK(classify_window(f) == static_cast<int>(FieldClass::NORMAL));
}

static void test_field_model_handshake_flood() {
    float f[FIELD_MODEL_NUM_FEATURES] = {12.0f, 10.0f, 0, 0, 0, 0, -55.0f, 2.0f, 0.5f, 3.0f};
    CHECK(classify_window(f) == static_cast<int>(FieldClass::FLOOD));
}

static void test_field_model_replay_campaign() {
    float f[FIELD_MODEL_NUM_FEATURES] = {0.2f, 0, 6.0f, 0, 0, 0, -55.0f, 2.0f, 0.5f, 3.0f};
    CHECK(classify_window(f) == static_cast<int>(FieldClass::REPLAY));
}

static void test_field_model_impersonation() {
    float f[FIELD_MODEL_NUM_FEATURES] = {0.2f, 0, 0, 4.0f, 0, 0, -55.0f, 2.0f, 0.5f, 3.0f};
    CHECK(classify_window(f) == static_cast<int>(FieldClass::IMPERSONATION));
}

static void test_field_model_weak_link() {
    float f[FIELD_MODEL_NUM_FEATURES] = {0.2f, 0, 0, 0, 0, 0, -80.0f, 25.0f, 15.0f, 60.0f};
    CHECK(classify_window(f) == static_cast<int>(FieldClass::WEAK_LINK));
}

// ---------------------------------------------------------------------
// Cookie challenge (v4: handshake-flood mitigation, brief v4)
// ---------------------------------------------------------------------

static void test_cookie_generate_is_deterministic() {
    CookieChallenge c(12345);
    uint8_t a[COOKIE_LEN], b[COOKIE_LEN];
    c.generate(1, 100, a);
    c.generate(1, 100, b);
    CHECK(std::memcmp(a, b, COOKIE_LEN) == 0);
}

static void test_cookie_verify_accepts_freshly_generated() {
    CookieChallenge c(0xABCDEF01);
    uint32_t now = 10000;
    uint8_t cookie[COOKIE_LEN];
    c.generate(3, CookieChallenge::time_window_for(now), cookie);
    CHECK(c.verify(3, now, cookie));
}

static void test_cookie_verify_rejects_wrong_sender() {
    CookieChallenge c(42);
    uint32_t now = 5000;
    uint8_t cookie[COOKIE_LEN];
    c.generate(1, CookieChallenge::time_window_for(now), cookie);
    CHECK(!c.verify(2, now, cookie)); // same window, different claimed sender
}

static void test_cookie_verify_rejects_garbage() {
    CookieChallenge c(999);
    uint8_t garbage[COOKIE_LEN] = {1, 2, 3, 4, 5, 6, 7, 8};
    CHECK(!c.verify(1, 1000, garbage));
}

static void test_cookie_verify_accepts_previous_window() {
    CookieChallenge c(7);
    uint32_t issue_time = 4 * COOKIE_WINDOW_MS + 100; // well inside window 4
    uint8_t cookie[COOKIE_LEN];
    c.generate(9, CookieChallenge::time_window_for(issue_time), cookie);

    // Verified slightly later, now in window 5 -- still accepted (tolerance
    // for a request arriving just after the boundary).
    uint32_t verify_time = 5 * COOKIE_WINDOW_MS + 50;
    CHECK(CookieChallenge::time_window_for(verify_time) == CookieChallenge::time_window_for(issue_time) + 1);
    CHECK(c.verify(9, verify_time, cookie));
}

static void test_cookie_verify_rejects_too_old_window() {
    CookieChallenge c(7);
    uint8_t cookie[COOKIE_LEN];
    c.generate(9, 0, cookie); // window 0

    // Two windows later: outside the current-or-previous tolerance.
    uint32_t verify_time = 2 * COOKIE_WINDOW_MS + 50;
    CHECK(!c.verify(9, verify_time, cookie));
}

static void test_cookie_different_secrets_disagree() {
    CookieChallenge c1(111);
    CookieChallenge c2(222);
    uint8_t a[COOKIE_LEN], b[COOKIE_LEN];
    c1.generate(1, 5, a);
    c2.generate(1, 5, b);
    CHECK(std::memcmp(a, b, COOKIE_LEN) != 0);
}

// ---------------------------------------------------------------------
// Energy token bucket (v4: EnergyGate budget)
// ---------------------------------------------------------------------

static void test_energy_budget_starts_full_by_default() {
    EnergyBudget b(/*capacity_j=*/10.0f, /*refill_rate_j_per_s=*/1.0f);
    CHECK(b.balance_j() == 10.0f);
    CHECK(!b.exhausted());
}

static void test_energy_budget_starts_at_given_initial() {
    EnergyBudget b(10.0f, 1.0f, /*initial_j=*/2.5f);
    CHECK(b.balance_j() == 2.5f);
}

static void test_energy_budget_initial_clamped_to_capacity() {
    EnergyBudget b(10.0f, 1.0f, /*initial_j=*/999.0f);
    CHECK(b.balance_j() == 10.0f);
}

static void test_energy_budget_spend_deducts_and_succeeds() {
    EnergyBudget b(10.0f, 0.0f); // no refill, isolate the spend logic
    CHECK(b.spend(3.0f, 0));
    CHECK(b.balance_j() == 7.0f);
}

static void test_energy_budget_spend_fails_when_insufficient() {
    EnergyBudget b(5.0f, 0.0f);
    CHECK(!b.spend(6.0f, 0));
    CHECK(b.balance_j() == 5.0f); // untouched on failure
}

static void test_energy_budget_refills_over_time() {
    EnergyBudget b(10.0f, /*refill_rate_j_per_s=*/2.0f, /*initial_j=*/0.0f);
    b.tick(0);            // establish the clock, no refill yet
    b.tick(1000);          // 1s elapsed @ 2 J/s
    CHECK(b.balance_j() == 2.0f);
}

static void test_energy_budget_refill_clamped_to_capacity() {
    EnergyBudget b(5.0f, 10.0f, /*initial_j=*/0.0f);
    b.tick(0);
    b.tick(10000); // would refill 100J at 10J/s over 10s -- clamped to capacity
    CHECK(b.balance_j() == 5.0f);
}

static void test_energy_budget_can_afford_does_not_deduct() {
    EnergyBudget b(10.0f, 0.0f);
    CHECK(b.can_afford(4.0f, 0));
    CHECK(b.balance_j() == 10.0f); // can_afford is a query, not a spend
}

static void test_energy_budget_exhausted_flag() {
    EnergyBudget b(1.0f, 0.0f, /*initial_j=*/0.0f);
    CHECK(b.exhausted());
    b.credit(0.5f);
    CHECK(!b.exhausted());
}

static void test_energy_budget_credit_clamped_and_floored() {
    EnergyBudget b(10.0f, 0.0f, 0.0f);
    b.credit(999.0f);
    CHECK(b.balance_j() == 10.0f);
}

// ---------------------------------------------------------------------
// EnergyGate rule-based score stand-in
// ---------------------------------------------------------------------
// Feature order: hs_per_s, hs_fail, frag_complete_pct, loss_pct, dup_pct,
// rssi_mean, rssi_var, battery_pct.

static void test_energygate_healthy_sender_scores_high() {
    float f[ENERGYGATE_NUM_FEATURES] = {0.2f, 0, -55.0f, 2.0f, 0.0f, 0.0f, 100.0f, 80.0f};
    float s = energygate_score(f);
    CHECK(s > 0.8f);
    CHECK(s <= 1.0f);
}

static void test_energygate_flooding_sender_scores_low() {
    float f[ENERGYGATE_NUM_FEATURES] = {20.0f, 18.0f, -70.0f, 30.0f, 40.0f, 30.0f, 10.0f, 50.0f};
    float s = energygate_score(f);
    CHECK(s < 0.3f);
    CHECK(s >= 0.0f);
}

static void test_energygate_score_bounded() {
    float f_lo[ENERGYGATE_NUM_FEATURES] = {1000.0f, 1000.0f, -100.0f, 500.0f, 100.0f, 100.0f, 0.0f, 0.0f};
    float f_hi[ENERGYGATE_NUM_FEATURES] = {0.0f, 0.0f, -30.0f, 0.0f, 0.0f, 0.0f, 100.0f, 100.0f};
    CHECK(energygate_score(f_lo) >= 0.0f);
    CHECK(energygate_score(f_lo) <= 1.0f);
    CHECK(energygate_score(f_hi) >= 0.0f);
    CHECK(energygate_score(f_hi) <= 1.0f);
}

// Pins the feature ORDER to ml/sentinel_ml/energygate.py's FEATURE_ORDER, so
// a future reshuffle can't silently feed one signal into another's slot.
static void test_energygate_feature_order_matches_ml() {
    CHECK(EG_HS_PER_S == 0);
    CHECK(EG_HS_FAIL == 1);
    CHECK(EG_RSSI_MEAN == 2);
    CHECK(EG_RSSI_VAR == 3);
    CHECK(EG_LOSS_PCT == 4);
    CHECK(EG_DUP_PCT == 5);
    CHECK(EG_FRAG_COMPLETE_PCT == 6);
    CHECK(EG_BATTERY_PCT == 7);
}
// The two slot tests below pin the rule-based stand-in's behaviour. A trained
// tree only splits on the features that carried signal in its training data
// (the simulated one ignores rssi_var and frag_complete_pct), so they are
// skipped when the trained model is compiled in; order is still pinned above.
static void test_energygate_reads_frag_complete_from_slot_6() {
    if (energygate_uses_trained_model()) return;
    float good[ENERGYGATE_NUM_FEATURES] = {0.2f, 0, -55.0f, 2.0f, 0.0f, 0.0f, 100.0f, 80.0f};
    float bad[ENERGYGATE_NUM_FEATURES]  = {0.2f, 0, -55.0f, 2.0f, 0.0f, 0.0f, 0.0f, 80.0f};
    CHECK(energygate_score(bad) < energygate_score(good));
}
static void test_energygate_reads_rssi_var_from_slot_3() {
    if (energygate_uses_trained_model()) return;
    float calm[ENERGYGATE_NUM_FEATURES]    = {0.2f, 0, -55.0f, 2.0f, 0.0f, 0.0f, 100.0f, 80.0f};
    float erratic[ENERGYGATE_NUM_FEATURES] = {0.2f, 0, -55.0f, 40.0f, 0.0f, 0.0f, 100.0f, 80.0f};
    CHECK(energygate_score(erratic) < energygate_score(calm));
}

// ---------------------------------------------------------------------
// gate_policy: the admission decision, per DEFENSE mode (brief v4 s.6)
// ---------------------------------------------------------------------

static GateInputs gate_in(float p, bool cookie = false, uint32_t since = NEVER_SEEN) {
    GateInputs in;
    in.prob_real = p;
    in.cookie_echoed = cookie;
    in.ms_since_last_attempt = since;
    return in;
}

static void test_gate_none_always_spends_and_never_touches_budget() {
    EnergyBudget b(1.0f, 0.0f, 0.0f); // empty bucket
    GatePolicyConfig cfg;
    CHECK(decide_admission(DefenseMode::NONE, gate_in(0.0f), b, cfg, 1000) == GateAction::SPEND);
    CHECK(b.balance_j() == 0.0f);
}
static void test_gate_ratelimit_drops_a_flood_passes_a_slow_drip() {
    EnergyBudget b(10.0f, 0.0f);
    GatePolicyConfig cfg; // 10 s per sender
    CHECK(decide_admission(DefenseMode::RATELIMIT, gate_in(0.0f, false, NEVER_SEEN), b, cfg, 0) == GateAction::SPEND);
    CHECK(decide_admission(DefenseMode::RATELIMIT, gate_in(0.0f, false, 50), b, cfg, 50) == GateAction::DROP);        // flood
    CHECK(decide_admission(DefenseMode::RATELIMIT, gate_in(0.0f, false, 60000), b, cfg, 60000) == GateAction::SPEND); // ~1/min drip gets through
    CHECK(b.balance_j() == 10.0f);
}
static void test_gate_cookie_challenges_until_echoed() {
    EnergyBudget b(10.0f, 0.0f);
    GatePolicyConfig cfg;
    CHECK(decide_admission(DefenseMode::COOKIE, gate_in(0.0f, false), b, cfg, 0) == GateAction::CHALLENGE);
    CHECK(decide_admission(DefenseMode::COOKIE, gate_in(0.0f, true), b, cfg, 0) == GateAction::SPEND);
    CHECK(b.balance_j() == 10.0f);
}
static void test_gate_spends_on_a_confident_score_and_charges_the_budget() {
    EnergyBudget b(1.0f, 0.0f);
    GatePolicyConfig cfg;
    cfg.handshake_cost_j = 0.25f;
    CHECK(decide_admission(DefenseMode::GATE, gate_in(0.9f), b, cfg, 0) == GateAction::SPEND);
    CHECK(b.balance_j() > 0.74f && b.balance_j() < 0.76f);
}
static void test_gate_challenges_a_middling_score_without_charging() {
    EnergyBudget b(1.0f, 0.0f);
    GatePolicyConfig cfg;
    cfg.handshake_cost_j = 0.25f;
    CHECK(decide_admission(DefenseMode::GATE, gate_in(0.5f), b, cfg, 0) == GateAction::CHALLENGE);
    CHECK(b.balance_j() == 1.0f);
}
static void test_gate_drops_a_low_score() {
    EnergyBudget b(1.0f, 0.0f);
    GatePolicyConfig cfg;
    CHECK(decide_admission(DefenseMode::GATE, gate_in(0.1f), b, cfg, 0) == GateAction::DROP);
}
static void test_gate_admits_a_returned_cookie_on_recheck() {
    EnergyBudget b(1.0f, 0.0f);
    GatePolicyConfig cfg;
    cfg.handshake_cost_j = 0.25f;
    CHECK(decide_admission(DefenseMode::GATE, gate_in(0.5f, true), b, cfg, 0) == GateAction::SPEND);
    CHECK(b.balance_j() < 1.0f);
    // a returned cookie does not rescue a sender the model distrusts
    CHECK(decide_admission(DefenseMode::GATE, gate_in(0.1f, true), b, cfg, 0) == GateAction::DROP);
}
static void test_gate_drops_when_the_budget_cannot_pay_for_a_handshake() {
    EnergyBudget b(1.0f, 0.0f, 0.1f); // less than one handshake left
    GatePolicyConfig cfg;
    cfg.handshake_cost_j = 0.25f;
    CHECK(decide_admission(DefenseMode::GATE, gate_in(0.9f), b, cfg, 0) == GateAction::DROP);
    CHECK(decide_admission(DefenseMode::GATE, gate_in(0.5f), b, cfg, 0) == GateAction::DROP);
    CHECK(b.balance_j() > 0.09f && b.balance_j() < 0.11f);
}
static void test_gate_budget_refills_and_admits_again() {
    EnergyBudget b(1.0f, 1.0f, 0.0f); // 1 J/s refill
    GatePolicyConfig cfg;
    cfg.handshake_cost_j = 0.25f;
    b.tick(0);
    CHECK(decide_admission(DefenseMode::GATE, gate_in(0.9f), b, cfg, 0) == GateAction::DROP);
    CHECK(decide_admission(DefenseMode::GATE, gate_in(0.9f), b, cfg, 500) == GateAction::SPEND);
}
static void test_defense_mode_names_round_trip() {
    const char* names[] = {"none", "ratelimit", "cookie", "gate"};
    for (const char* n : names) {
        DefenseMode m;
        CHECK(parse_defense_mode(n, m));
        CHECK(std::strcmp(defense_mode_name(m), n) == 0);
    }
    DefenseMode m = DefenseMode::GATE;
    CHECK(!parse_defense_mode("GATE", m));    // exact lowercase, like the contract
    CHECK(!parse_defense_mode("shields", m));
    CHECK(!parse_defense_mode(nullptr, m));
    CHECK(m == DefenseMode::GATE);            // untouched on failure
}
static void test_gate_action_contract_vocabulary() {
    CHECK(std::strcmp(gate_action_name(GateAction::SPEND), "spend") == 0);
    CHECK(std::strcmp(gate_action_name(GateAction::CHALLENGE), "challenge") == 0);
    CHECK(std::strcmp(gate_action_name(GateAction::DROP), "drop") == 0);
    CHECK(std::strcmp(gate_action_severity(GateAction::SPEND), "info") == 0);
    CHECK(std::strcmp(gate_action_severity(GateAction::CHALLENGE), "low") == 0);
    CHECK(std::strcmp(gate_action_severity(GateAction::DROP), "medium") == 0);
}

// ---------------------------------------------------------------------
// gate_msgs: GATE_REPORT (field-1 -> gateway), CONTROL (gateway -> field-1)
// ---------------------------------------------------------------------

static void test_new_msg_types_are_valid_on_the_wire() {
    CHECK(is_valid_msg_type(static_cast<uint8_t>(MsgType::GATE_REPORT)));
    CHECK(is_valid_msg_type(static_cast<uint8_t>(MsgType::CONTROL)));
    CHECK(!is_valid_msg_type(0x09));
    PacketHeader h;
    h.type = MsgType::GATE_REPORT;
    h.sender = 1;
    uint8_t buf[HEADER_SIZE];
    CHECK(h.serialize(buf, sizeof(buf)) == HEADER_SIZE);
    PacketHeader back;
    CHECK(PacketHeader::deserialize(buf, sizeof(buf), back));
    CHECK(back.type == MsgType::GATE_REPORT);
}
static void test_gate_report_round_trip() {
    GateReport r;
    r.sender = 3;
    r.action = GateAction::CHALLENGE;
    r.mode = DefenseMode::GATE;
    r.budget_exhausted_edge = true;
    r.prob_real = 0.21f;
    r.budget_j = 12.5f;
    r.budget_max_j = 40.0f;
    uint8_t buf[GATE_REPORT_LEN];
    CHECK(serialize_gate_report(r, buf, sizeof(buf)) == GATE_REPORT_LEN);
    GateReport back;
    CHECK(deserialize_gate_report(buf, sizeof(buf), back));
    CHECK(back.sender == 3);
    CHECK(back.action == GateAction::CHALLENGE);
    CHECK(back.mode == DefenseMode::GATE);
    CHECK(back.budget_exhausted_edge);
    CHECK(back.prob_real == 0.21f);
    CHECK(back.budget_j == 12.5f);
    CHECK(back.budget_max_j == 40.0f);
}
static void test_gate_report_is_big_endian() {
    GateReport r;
    r.budget_max_j = 40.0f; // IEEE-754 0x42200000
    uint8_t buf[GATE_REPORT_LEN];
    serialize_gate_report(r, buf, sizeof(buf));
    CHECK(buf[12] == 0x42 && buf[13] == 0x20 && buf[14] == 0x00 && buf[15] == 0x00);
}
static void test_gate_report_rejects_corruption() {
    GateReport r;
    uint8_t buf[GATE_REPORT_LEN];
    serialize_gate_report(r, buf, sizeof(buf));
    GateReport back;
    CHECK(!deserialize_gate_report(buf, GATE_REPORT_LEN - 1, back)); // short
    uint8_t bad_action[GATE_REPORT_LEN];
    std::memcpy(bad_action, buf, sizeof(buf));
    bad_action[1] = 7;
    CHECK(!deserialize_gate_report(bad_action, sizeof(bad_action), back));
    uint8_t bad_mode[GATE_REPORT_LEN];
    std::memcpy(bad_mode, buf, sizeof(buf));
    bad_mode[2] = 9;
    CHECK(!deserialize_gate_report(bad_mode, sizeof(bad_mode), back));
    uint8_t bad_flags[GATE_REPORT_LEN];
    std::memcpy(bad_flags, buf, sizeof(buf));
    bad_flags[3] = 0x80;
    CHECK(!deserialize_gate_report(bad_flags, sizeof(bad_flags), back));
    CHECK(serialize_gate_report(r, buf, GATE_REPORT_LEN - 1) == 0);
}
static void test_control_sequencer_orders_without_a_shared_clock() {
    ControlSequencer q;
    CHECK(q.accept(7, 0));    // first message ever
    CHECK(q.accept(7, 1));    // newer
    CHECK(!q.accept(7, 1));   // duplicate
    CHECK(!q.accept(7, 0));   // older (a replay within the epoch)
    CHECK(q.accept(9, 0));    // gateway rebooted: new epoch restarts the count
    CHECK(q.accept(9, 5));
    CHECK(!q.accept(9, 4));
}
static void test_control_round_trip_and_rejects_bad_mode() {
    ControlMsg m;
    m.kind = ControlKind::DEFENSE;
    m.value = static_cast<uint8_t>(DefenseMode::COOKIE);
    uint8_t buf[CONTROL_LEN];
    CHECK(serialize_control(m, buf, sizeof(buf)) == CONTROL_LEN);
    ControlMsg back;
    CHECK(deserialize_control(buf, sizeof(buf), back));
    CHECK(back.value == static_cast<uint8_t>(DefenseMode::COOKIE));
    uint8_t bad_mode[CONTROL_LEN] = {1, 4};
    CHECK(!deserialize_control(bad_mode, sizeof(bad_mode), back));
    uint8_t bad_kind[CONTROL_LEN] = {2, 0};
    CHECK(!deserialize_control(bad_kind, sizeof(bad_kind), back));
    CHECK(!deserialize_control(buf, 1, back));
}

int main() {
    RUN(test_header_roundtrip_basic);
    RUN(test_header_all_msg_types_roundtrip);
    RUN(test_header_rejects_short_buffer);
    RUN(test_header_rejects_bad_version);
    RUN(test_header_rejects_bad_msg_type);
    RUN(test_header_rejects_frag_i_out_of_range);

    RUN(test_fragment_small_payload_single_fragment);
    RUN(test_fragment_large_payload_multi_fragment_and_reassembles);
    RUN(test_fragment_out_of_order_reassembles);
    RUN(test_fragment_duplicate_fragment_ignored);
    RUN(test_fragment_timeout_expires_incomplete_stream);
    RUN(test_fragment_stream_cap_rejects_new_streams_when_full);

    RUN(test_replay_first_packet_accepted);
    RUN(test_replay_monotonic_sequence_all_accepted);
    RUN(test_replay_exact_duplicate_rejected_as_duplicate);
    RUN(test_replay_old_seq_outside_window_rejected);
    RUN(test_replay_in_window_out_of_order_accepted_once);
    RUN(test_replay_captured_and_replayed_packet_rejected);
    RUN(test_replay_stale_timestamp_rejected_even_with_fresh_seq);
    RUN(test_replay_reset_clears_peer_state);
    RUN(test_replay_peers_are_independent);

    RUN(test_field_model_normal_window);
    RUN(test_field_model_handshake_flood);
    RUN(test_field_model_replay_campaign);
    RUN(test_field_model_impersonation);
    RUN(test_field_model_weak_link);

    RUN(test_cookie_generate_is_deterministic);
    RUN(test_cookie_verify_accepts_freshly_generated);
    RUN(test_cookie_verify_rejects_wrong_sender);
    RUN(test_cookie_verify_rejects_garbage);
    RUN(test_cookie_verify_accepts_previous_window);
    RUN(test_cookie_verify_rejects_too_old_window);
    RUN(test_cookie_different_secrets_disagree);

    RUN(test_energy_budget_starts_full_by_default);
    RUN(test_energy_budget_starts_at_given_initial);
    RUN(test_energy_budget_initial_clamped_to_capacity);
    RUN(test_energy_budget_spend_deducts_and_succeeds);
    RUN(test_energy_budget_spend_fails_when_insufficient);
    RUN(test_energy_budget_refills_over_time);
    RUN(test_energy_budget_refill_clamped_to_capacity);
    RUN(test_energy_budget_can_afford_does_not_deduct);
    RUN(test_energy_budget_exhausted_flag);
    RUN(test_energy_budget_credit_clamped_and_floored);

    RUN(test_energygate_healthy_sender_scores_high);
    RUN(test_energygate_flooding_sender_scores_low);
    RUN(test_energygate_score_bounded);
    RUN(test_energygate_feature_order_matches_ml);
    RUN(test_energygate_reads_frag_complete_from_slot_6);
    RUN(test_energygate_reads_rssi_var_from_slot_3);

    RUN(test_gate_none_always_spends_and_never_touches_budget);
    RUN(test_gate_ratelimit_drops_a_flood_passes_a_slow_drip);
    RUN(test_gate_cookie_challenges_until_echoed);
    RUN(test_gate_spends_on_a_confident_score_and_charges_the_budget);
    RUN(test_gate_challenges_a_middling_score_without_charging);
    RUN(test_gate_drops_a_low_score);
    RUN(test_gate_admits_a_returned_cookie_on_recheck);
    RUN(test_gate_drops_when_the_budget_cannot_pay_for_a_handshake);
    RUN(test_gate_budget_refills_and_admits_again);
    RUN(test_defense_mode_names_round_trip);
    RUN(test_gate_action_contract_vocabulary);

    RUN(test_new_msg_types_are_valid_on_the_wire);
    RUN(test_gate_report_round_trip);
    RUN(test_gate_report_is_big_endian);
    RUN(test_gate_report_rejects_corruption);
    RUN(test_control_round_trip_and_rejects_bad_mode);
    RUN(test_control_sequencer_orders_without_a_shared_clock);

    std::printf("\n%d passed, %d failed\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
