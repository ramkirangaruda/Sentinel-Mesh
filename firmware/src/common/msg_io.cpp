#ifdef ARDUINO
#include "common/msg_io.h"
#include "common/aead.h"
#include "common/mesh_transport.h"
#include "sentinel_proto/fragment.h"
#include <Arduino.h>
#include <cstring>

namespace sentinel {

size_t send_message(const PacketHeader& tmpl, const uint8_t* payload, size_t len) {
    auto frags = Fragmenter::split(tmpl, payload, len);
    if (frags.empty()) return 0;
    size_t sent = 0;
    for (auto& f : frags) {
        if (mesh::broadcast(f.data(), f.size())) sent++;
    }
    return sent == frags.size() ? sent : 0;
}

void Session::clear() {
    active = false;
    memset(k_tx, 0, sizeof(k_tx));
    memset(k_rx, 0, sizeof(k_rx));
    tx_seq = 0;
    replay.reset(peer);
}

void aad_for(const PacketHeader& hdr, uint8_t out[HEADER_SIZE]) {
    PacketHeader h = hdr;
    h.frag_i = 0;
    h.frag_n = 1;
    h.serialize(out, HEADER_SIZE);
}

bool session_send(Session& s, uint8_t self_id, MsgType type, uint32_t now_ms,
                  const uint8_t* pt, size_t pt_len) {
    if (!s.active) return false;
    PacketHeader h;
    h.type = type;
    h.sender = self_id;
    h.epoch = s.epoch;
    h.seq = s.tx_seq++;
    h.time_ms = s.session_ms(now_ms);
    uint8_t aad[HEADER_SIZE];
    aad_for(h, aad);
    uint8_t nonce[aead::GCM_NONCE_LEN];
    aead::build_nonce(h.sender, h.epoch, h.seq, nonce);
    std::vector<uint8_t> body;
    if (!aead::encrypt(s.k_tx, nonce, aad, sizeof(aad), pt, pt_len, body)) return false;
    return send_message(h, body.data(), body.size()) > 0;
}

OpenResult session_open(Session& s, const PacketHeader& hdr, const uint8_t* body, size_t body_len,
                        uint32_t now_ms, std::vector<uint8_t>& pt) {
    if (!s.active) return OpenResult::NO_SESSION;
    if (hdr.epoch != s.epoch) return OpenResult::WRONG_EPOCH;
    // Authenticate first: replay state must only ever advance for genuine packets.
    uint8_t aad[HEADER_SIZE];
    aad_for(hdr, aad);
    uint8_t nonce[aead::GCM_NONCE_LEN];
    aead::build_nonce(hdr.sender, hdr.epoch, hdr.seq, nonce);
    if (!aead::decrypt(s.k_rx, nonce, aad, sizeof(aad), body, body_len, pt)) return OpenResult::BAD_TAG;
    switch (s.replay.check(hdr.sender, hdr.seq, hdr.time_ms, s.session_ms(now_ms))) {
        case ReplayFilter::Result::ACCEPT: return OpenResult::OK;
        case ReplayFilter::Result::DUPLICATE: return OpenResult::DUPLICATE;
        case ReplayFilter::Result::REPLAY_REJECTED: return OpenResult::REPLAY;
        case ReplayFilter::Result::STALE_TIMESTAMP: return OpenResult::STALE;
    }
    return OpenResult::REPLAY;
}

} // namespace sentinel
#endif // ARDUINO
