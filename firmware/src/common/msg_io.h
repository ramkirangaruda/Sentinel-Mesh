#pragma once
// Fragment + broadcast helper and the encrypted DATA path (AES-256-GCM, header
// as AAD) shared by field_node and gateway. ESP32-only (mbedtls, ESP-NOW).

#include <cstddef>
#include <cstdint>
#include <vector>
#include "sentinel_proto/packet.h"
#include "sentinel_proto/replay.h"

namespace sentinel {

// Splits `payload` under `tmpl` (sender/epoch/seq/type/time_ms/prio) and
// broadcasts every fragment. Returns the number of frames sent (0 on failure).
size_t send_message(const PacketHeader& tmpl, const uint8_t* payload, size_t len);

struct Session {
    bool active = false;
    uint8_t peer = 0;
    uint16_t epoch = 0;
    uint8_t k_tx[32] = {0};
    uint8_t k_rx[32] = {0};
    uint32_t tx_seq = 0;
    uint32_t start_ms = 0;      // millis() when the session became active (our side)
    ReplayFilter replay;

    void clear();
    uint32_t session_ms(uint32_t now_ms) const { return now_ms - start_ms; }
};

// Header bytes used as AEAD associated data: the packet header with the
// fragment fields normalised (frag_i=0, frag_n=1), so every fragment of one
// message authenticates against the same AAD.
void aad_for(const PacketHeader& hdr, uint8_t out[HEADER_SIZE]);

// Encrypts `pt` into a DATA-style message of `type` and sends it.
bool session_send(Session& s, uint8_t self_id, MsgType type, uint32_t now_ms,
                  const uint8_t* pt, size_t pt_len);

// Verifies replay window + AEAD tag of a reassembled message. On success
// returns true and fills `pt`.
enum class OpenResult : uint8_t { OK, NO_SESSION, WRONG_EPOCH, REPLAY, STALE, DUPLICATE, BAD_TAG };
OpenResult session_open(Session& s, const PacketHeader& hdr, const uint8_t* body, size_t body_len,
                        uint32_t now_ms, std::vector<uint8_t>& pt);

} // namespace sentinel
