// Host test for the PQC handshake, against the real vendored PQClean code.
// Build/run: tools/run_pqc_tests.sh   (level 1 and level 3)
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <vector>
#include "sentinel_pqc/pqc_handshake.h"
#include "sentinel_proto/fragment.h"

using namespace sentinel::pqc;

static int g_fail = 0;
#define CHECK(c) do { if (!(c)) { printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #c); g_fail++; } } while (0)

struct Counts { int n[6] = {0}; };
static void hook(Phase p, bool begin, void* u) {
    if (begin) static_cast<Counts*>(u)->n[static_cast<int>(p)]++;
}

struct Keys { std::vector<uint8_t> pk, sk; };
static Keys sig_keys() {
    Keys k; k.pk.resize(SIG_PK_BYTES); k.sk.resize(SIG_SK_BYTES);
    CHECK(SM_SIG(crypto_sign_keypair)(k.pk.data(), k.sk.data()) == 0);
    return k;
}

int main() {
    printf("%s + %s : HELLO=%zu RESPONSE=%zu CONFIRM=%zu bytes\n", SM_PQC_KEM_NAME, SM_PQC_SIG_NAME,
           HELLO_LEN, RESPONSE_LEN, CONFIRM_LEN);
    Keys gw = sig_keys(), f1 = sig_keys(), atk = sig_keys();
    const uint8_t GW = 2, F1 = 1, ATK = 3;

    static InitiatorState I; static ResponderState R;
    std::vector<uint8_t> hello(HELLO_LEN), resp(RESPONSE_LEN), conf(CONFIRM_LEN);
    Counts ci, cr;
    Hooks hi{hook, &ci}, hr{hook, &cr};

    // --- happy path
    CHECK(initiator_make_hello(I, GW, F1, gw.sk.data(), hi, hello.data()) == Result::OK);
    uint8_t cookie[COOKIE_BYTES] = {1,2,3,4,5,6,7,8};
    hello_set_cookie(hello.data(), cookie);   // cookie is outside the signed transcript
    CHECK(responder_handle_hello(R, F1, GW, gw.pk.data(), f1.sk.data(), hello.data(), hello.size(), hr, resp.data()) == Result::OK);
    SessionKeys ki, kr;
    CHECK(initiator_handle_response(I, GW, F1, f1.pk.data(), resp.data(), resp.size(), hi, ki, conf.data()) == Result::OK);
    CHECK(responder_handle_confirm(R, conf.data(), conf.size(), kr) == Result::OK);
    CHECK(memcmp(ki.k_i2r, kr.k_i2r, KEY_BYTES) == 0);
    CHECK(memcmp(ki.k_r2i, kr.k_r2i, KEY_BYTES) == 0);
    CHECK(memcmp(ki.k_i2r, ki.k_r2i, KEY_BYTES) != 0);
    // phase accounting: this is what the energy rig will attribute
    CHECK(ci.n[(int)Phase::KEM_KEYGEN] == 1 && ci.n[(int)Phase::SIG_SIGN] == 1);
    CHECK(ci.n[(int)Phase::SIG_VERIFY] == 1 && ci.n[(int)Phase::KEM_DECAPS] == 1);
    CHECK(cr.n[(int)Phase::SIG_VERIFY] == 1 && cr.n[(int)Phase::KEM_ENCAPS] == 1 && cr.n[(int)Phase::SIG_SIGN] == 1);

    // --- forged HELLO (random signature) costs the responder only a verify
    {
        std::vector<uint8_t> bad = hello;
        for (size_t i = 0; i < SIG_BYTES; i++) bad[COOKIE_BYTES + NONCE_BYTES + KEM_PK_BYTES + i] = (uint8_t)rand();
        Counts c; Hooks h{hook, &c};
        std::vector<uint8_t> out(RESPONSE_LEN);
        CHECK(responder_handle_hello(R, F1, GW, gw.pk.data(), f1.sk.data(), bad.data(), bad.size(), h, out.data()) == Result::BAD_SIGNATURE);
        CHECK(c.n[(int)Phase::SIG_VERIFY] == 1 && c.n[(int)Phase::KEM_ENCAPS] == 0 && c.n[(int)Phase::SIG_SIGN] == 0);
        CHECK(!R.valid);
    }
    // --- HELLO signed by the attacker's key but claiming to be the gateway
    {
        static InitiatorState A; std::vector<uint8_t> h2(HELLO_LEN), out(RESPONSE_LEN);
        CHECK(initiator_make_hello(A, GW, F1, atk.sk.data(), Hooks{}, h2.data()) == Result::OK);
        CHECK(responder_handle_hello(R, F1, GW, gw.pk.data(), f1.sk.data(), h2.data(), h2.size(), Hooks{}, out.data()) == Result::BAD_SIGNATURE);
    }
    // --- tampered KEM public key / nonce / ids are rejected (transcript binding)
    {
        std::vector<uint8_t> out(RESPONSE_LEN);
        std::vector<uint8_t> t = hello; t[COOKIE_BYTES + NONCE_BYTES + 5] ^= 1;
        CHECK(responder_handle_hello(R, F1, GW, gw.pk.data(), f1.sk.data(), t.data(), t.size(), Hooks{}, out.data()) == Result::BAD_SIGNATURE);
        t = hello; t[COOKIE_BYTES + 3] ^= 1;
        CHECK(responder_handle_hello(R, F1, GW, gw.pk.data(), f1.sk.data(), t.data(), t.size(), Hooks{}, out.data()) == Result::BAD_SIGNATURE);
        // same bytes, responder believes the sender is the attacker id: verify must fail (id is in th1)
        CHECK(responder_handle_hello(R, F1, ATK, atk.pk.data(), f1.sk.data(), hello.data(), hello.size(), Hooks{}, out.data()) == Result::BAD_SIGNATURE);
        CHECK(responder_handle_hello(R, F1, GW, gw.pk.data(), f1.sk.data(), hello.data(), hello.size() - 1, Hooks{}, out.data()) == Result::BAD_LENGTH);
    }
    // --- tampered RESPONSE / CONFIRM
    {
        static InitiatorState I2; static ResponderState R2;
        std::vector<uint8_t> h(HELLO_LEN), rs(RESPONSE_LEN), cf(CONFIRM_LEN);
        CHECK(initiator_make_hello(I2, GW, F1, gw.sk.data(), Hooks{}, h.data()) == Result::OK);
        CHECK(responder_handle_hello(R2, F1, GW, gw.pk.data(), f1.sk.data(), h.data(), h.size(), Hooks{}, rs.data()) == Result::OK);
        SessionKeys k;
        std::vector<uint8_t> t = rs; t[NONCE_BYTES * 2 + 7] ^= 1;       // ciphertext bit
        InitiatorState save = I2;
        CHECK(initiator_handle_response(I2, GW, F1, f1.pk.data(), t.data(), t.size(), Hooks{}, k, cf.data()) == Result::BAD_SIGNATURE);
        t = rs; t[0] ^= 1;                                               // wrong nonce_i echo
        CHECK(initiator_handle_response(I2, GW, F1, f1.pk.data(), t.data(), t.size(), Hooks{}, k, cf.data()) == Result::BAD_BINDING);
        // response signed by the wrong key
        CHECK(initiator_handle_response(I2, GW, F1, atk.pk.data(), rs.data(), rs.size(), Hooks{}, k, cf.data()) == Result::BAD_SIGNATURE);
        CHECK(initiator_handle_response(I2, GW, F1, f1.pk.data(), rs.data(), rs.size(), Hooks{}, k, cf.data()) == Result::OK);
        // bad confirm tag, then the good one still works
        std::vector<uint8_t> bc = cf; bc[NONCE_BYTES + 1] ^= 1;
        SessionKeys kr;
        CHECK(responder_handle_confirm(R2, bc.data(), bc.size(), kr) == Result::BAD_TAG);
        CHECK(responder_handle_confirm(R2, cf.data(), cf.size(), kr) == Result::OK);
        CHECK(responder_handle_confirm(R2, cf.data(), cf.size(), kr) == Result::NO_STATE); // single use
        (void)save;
    }
    // --- two exchanges give independent keys
    {
        static InitiatorState Ia; static ResponderState Ra; SessionKeys k1, k2, kk;
        std::vector<uint8_t> h(HELLO_LEN), rs(RESPONSE_LEN), cf(CONFIRM_LEN);
        for (int round = 0; round < 2; round++) {
            CHECK(initiator_make_hello(Ia, GW, F1, gw.sk.data(), Hooks{}, h.data()) == Result::OK);
            CHECK(responder_handle_hello(Ra, F1, GW, gw.pk.data(), f1.sk.data(), h.data(), h.size(), Hooks{}, rs.data()) == Result::OK);
            CHECK(initiator_handle_response(Ia, GW, F1, f1.pk.data(), rs.data(), rs.size(), Hooks{}, round ? k2 : k1, cf.data()) == Result::OK);
            CHECK(responder_handle_confirm(Ra, cf.data(), cf.size(), kk) == Result::OK);
        }
        CHECK(memcmp(k1.k_i2r, k2.k_i2r, KEY_BYTES) != 0);
    }
    // --- the messages survive the real fragmenter/reassembler (ESP-NOW MTU), frame counts as expected
    {
        static InitiatorState If; static ResponderState Rf; SessionKeys k1, k2;
        std::vector<uint8_t> h(HELLO_LEN), rs(RESPONSE_LEN), cf(CONFIRM_LEN);
        CHECK(initiator_make_hello(If, GW, F1, gw.sk.data(), Hooks{}, h.data()) == Result::OK);
        sentinel::PacketHeader tmpl; tmpl.type = sentinel::MsgType::HELLO; tmpl.sender = GW; tmpl.epoch = 7; tmpl.seq = 1;
        auto frames = sentinel::Fragmenter::split(tmpl, h.data(), h.size());
        printf("HELLO -> %zu frames, RESPONSE -> ", frames.size());
        CHECK(!frames.empty() && frames.size() == (HELLO_LEN + 234) / 235);
        sentinel::Reassembler ra; std::vector<uint8_t> got; bool done = false;
        for (size_t i = frames.size(); i-- > 0;) {            // deliver in reverse order
            sentinel::PacketHeader ph;
            CHECK(sentinel::PacketHeader::deserialize(frames[i].data(), frames[i].size(), ph));
            done = ra.feed(ph, frames[i].data() + sentinel::HEADER_SIZE, frames[i].size() - sentinel::HEADER_SIZE, 0, got);
        }
        CHECK(done && got.size() == HELLO_LEN && memcmp(got.data(), h.data(), HELLO_LEN) == 0);
        CHECK(responder_handle_hello(Rf, F1, GW, gw.pk.data(), f1.sk.data(), got.data(), got.size(), Hooks{}, rs.data()) == Result::OK);
        auto rframes = sentinel::Fragmenter::split(tmpl, rs.data(), rs.size());
        printf("%zu frames\n", rframes.size());
        CHECK(!rframes.empty());
        CHECK(initiator_handle_response(If, GW, F1, f1.pk.data(), rs.data(), rs.size(), Hooks{}, k1, cf.data()) == Result::OK);
        CHECK(responder_handle_confirm(Rf, cf.data(), cf.size(), k2) == Result::OK);
    }
    printf(g_fail ? "FAILED (%d)\n" : "all pqc tests passed\n", g_fail);
    return g_fail ? 1 : 0;
}
