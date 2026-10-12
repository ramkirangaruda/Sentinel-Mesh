#pragma once
#include <cstdint>

// Shared node/message enums for the SentinelMesh mesh protocol.
// Kept dependency-free (no Arduino.h) so this header is usable both on
// ESP32 targets and in host-side unit tests.

namespace sentinel {

// Logical node ids on the mesh. Keep small — sender is a single byte on
// the wire (see packet.h).
enum class NodeId : uint8_t {
    FIELD_1  = 1,
    GATEWAY  = 2,
    ATTACKER = 3,
};

// Message types, per contracts/CONTRACT.md "Message types".
enum class MsgType : uint8_t {
    HELLO    = 0x01,
    RESPONSE = 0x02,
    CONFIRM  = 0x03,
    DATA     = 0x04,
    ACK      = 0x05,
    REKEY    = 0x06,
    // v4 EnergyGate (gate_msgs.h). EnergyGate runs on field-1, which has no
    // serial link during a run, so its decisions and its DEFENSE setting
    // travel over the mesh via the gateway.
    GATE_REPORT = 0x07, // field-1 -> gateway: one admission decision
    CONTROL     = 0x08, // gateway -> field-1: relays the console's DEFENSE <mode>
    // Phase 6 (paper): EnergyGate's CHALLENGE action on the wire. field-1 -> initiator,
    // payload = the 8-byte cookie (cookie.h) the initiator must echo in its next HELLO.
    CHALLENGE   = 0x09,
};

inline bool is_valid_msg_type(uint8_t v) {
    switch (v) {
        case static_cast<uint8_t>(MsgType::HELLO):
        case static_cast<uint8_t>(MsgType::RESPONSE):
        case static_cast<uint8_t>(MsgType::CONFIRM):
        case static_cast<uint8_t>(MsgType::DATA):
        case static_cast<uint8_t>(MsgType::ACK):
        case static_cast<uint8_t>(MsgType::REKEY):
        case static_cast<uint8_t>(MsgType::GATE_REPORT):
        case static_cast<uint8_t>(MsgType::CONTROL):
        case static_cast<uint8_t>(MsgType::CHALLENGE):
            return true;
        default:
            return false;
    }
}

// ML-KEM security levels the adaptive-crypto layer can pick between.
enum class KemLevel : uint16_t {
    KEM_512  = 512,
    KEM_768  = 768,
    KEM_1024 = 1024,
};

} // namespace sentinel
