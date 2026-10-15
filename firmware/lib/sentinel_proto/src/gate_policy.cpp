#include "sentinel_proto/gate_policy.h"

#include <cstring>

namespace sentinel {

const char* defense_mode_name(DefenseMode m) {
    switch (m) {
        case DefenseMode::NONE: return "none";
        case DefenseMode::RATELIMIT: return "ratelimit";
        case DefenseMode::COOKIE: return "cookie";
        case DefenseMode::GATE: return "gate";
    }
    return "none";
}

bool parse_defense_mode(const char* s, DefenseMode& out) {
    if (s == nullptr) return false;
    if (std::strcmp(s, "none") == 0) { out = DefenseMode::NONE; return true; }
    if (std::strcmp(s, "ratelimit") == 0) { out = DefenseMode::RATELIMIT; return true; }
    if (std::strcmp(s, "cookie") == 0) { out = DefenseMode::COOKIE; return true; }
    if (std::strcmp(s, "gate") == 0) { out = DefenseMode::GATE; return true; }
    return false;
}

bool defense_mode_from_byte(uint8_t v, DefenseMode& out) {
    if (v > static_cast<uint8_t>(DefenseMode::GATE)) return false;
    out = static_cast<DefenseMode>(v);
    return true;
}

const char* gate_action_name(GateAction a) {
    switch (a) {
        case GateAction::SPEND: return "spend";
        case GateAction::CHALLENGE: return "challenge";
        case GateAction::DROP: return "drop";
    }
    return "drop";
}

const char* gate_action_severity(GateAction a) {
    switch (a) {
        case GateAction::SPEND: return "info";
        case GateAction::CHALLENGE: return "low";
        case GateAction::DROP: return "medium";
    }
    return "medium";
}

bool gate_action_from_byte(uint8_t v, GateAction& out) {
    if (v > static_cast<uint8_t>(GateAction::DROP)) return false;
    out = static_cast<GateAction>(v);
    return true;
}

GateAction decide_admission(DefenseMode mode, const GateInputs& in, EnergyBudget& budget,
                            const GatePolicyConfig& cfg, uint32_t now_ms) {
    switch (mode) {
        case DefenseMode::NONE:
            return GateAction::SPEND;

        case DefenseMode::RATELIMIT:
            if (in.ms_since_last_attempt == NEVER_SEEN ||
                in.ms_since_last_attempt >= cfg.ratelimit_min_interval_ms) {
                return GateAction::SPEND;
            }
            return GateAction::DROP;

        case DefenseMode::COOKIE:
            return in.cookie_echoed ? GateAction::SPEND : GateAction::CHALLENGE;

        case DefenseMode::GATE:
            break;
    }

    // GATE -- see the rule list in gate_policy.h.
    if (in.prob_real >= cfg.spend_threshold && budget.spend(cfg.handshake_cost_j, now_ms)) {
        return GateAction::SPEND;
    }
    if (in.cookie_echoed && (cfg.challenge_low_scores || in.prob_real >= cfg.challenge_threshold) &&
        budget.spend(cfg.handshake_cost_j, now_ms)) {
        return GateAction::SPEND;
    }
    if (!budget.can_afford(cfg.handshake_cost_j, now_ms)) {
        return GateAction::DROP;
    }
    if (in.prob_real >= cfg.challenge_threshold) {
        return GateAction::CHALLENGE;
    }
    if (cfg.challenge_low_scores && budget.spend(cfg.challenge_cost_j, now_ms)) {
        return GateAction::CHALLENGE;
    }
    return GateAction::DROP;
}

} // namespace sentinel
