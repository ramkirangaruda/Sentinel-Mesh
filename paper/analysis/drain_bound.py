#!/usr/bin/env python3
"""Analytic worst-case drain bound for the ADAPTIVE / ADAPTIVE_SPOOF attacker (task S5 / E7).

  python paper/analysis/drain_bound.py [--seconds T] [--rx-mj-per-attempt X]

The claim (paper/writing/paper.md Section 8): even when EnergyGate's score is fooled into
spending or challenging on every attempt, the victim's *budgeted* energy drain is bounded by
the joule bucket's mechanics alone -- a property of firmware/lib/sentinel_proto/energy_budget.h,
independent of the classifier in energygate_model.h. What is NOT bounded by the budget is the
cost of receiving a HELLO's frames before the gate decides; that part is bounded instead by the
attacker's own pacing, which the ADAPTIVE attacker controls (it is the thing the paper's bound
must hold up against an attacker that tunes its pacer, not just the one firmware/src/attacker
ships with).

1. Budgeted drain (SPEND + CHALLENGE in policy v2; gate_policy.h, firmware/src/field_node/main.cpp)
   ---------------------------------------------------------------------------------------------
   EnergyBudget (energy_budget.h) is a bucket of capacity B joules, refilling at r J/s, that can
   never go negative and never spend more than it holds. For ANY sequence of spends over
   [0, T] (whatever the classifier admits), the total spent is at most the starting balance plus
   everything refilled in that time:

        total_spend(T) <= B + r*T                                                     (1)

   This holds however the attacker paces itself, however many of the 8 features it fools, and
   whatever SPEND/CHALLENGE mix the policy produces -- it needs nothing about energygate_score()
   beyond "it returns a number", because (1) is a property of EnergyBudget.spend()/tick(), proved
   by induction over calls (energy_budget.cpp: spend() refuses when balance_j_ < cost_j, and
   balance_j_ only increases by tick()'s bounded refill between spends). The long-run average
   budgeted power is bounded by the refill rate alone:

        avg_power(T) = total_spend(T) / T <= r + B/T   ->   r as T -> infinity            (2)

   So a budget-bounded attacker's worst-case long-run drain through the gate is exactly the
   refill rate r, whatever it does. The B/T term is the one-time head start from a full bucket.

2. Unbudgeted drain (reception + DROP's residual cost)
   -----------------------------------------------------
   DROP costs nothing from the budget, but field-1's radio still receives the HELLO's frames and
   the CPU still wakes for each one before EnergyGate decides (paper/decisions.md Phase 6 #6).
   This part is NOT bounded by the joule bucket -- it is bounded by how often the attacker can
   make an attempt, which for ADAPTIVE is the pacer's own cap (attacker_pacer.h PacerConfig):

        attempts/s <= max_in_window / (window_ms / 1000)                                  (3)

   and each attempt costs at most E_rx (the energy to receive one HELLO's frames, measured by
   S2/E2 as "energy per dropped HELLO" or estimated from frame count x per-frame RX energy; see
   --rx-mj-per-attempt below). So:

        unbudgeted_power <= (attempts/s) * E_rx                                           (4)

   Total worst-case victim power is (2) + (4). Note (4) depends on the ATTACKER's own choice of
   pacer config, not on firmware/src/attacker's shipped defaults -- an adaptive attacker could
   raise max_in_window arbitrarily (it costs the attacker nothing per se), but doing so raises
   hs_per_s and the SIMULATED-trained tree in energygate_model.h scores it down, turning more
   attempts into CHALLENGE (still budgeted) rather than SPEND; (1)-(2) is what still holds when
   that classifier-level defence is fooled or retrained away, which is the point of this bound.

PLACEHOLDER values: B, r, c_h, c_c below are gate_policy.h / field_node/main.cpp's current
placeholders (not yet measured on the rig -- task S2). E_rx has no measurement yet at all;
--rx-mj-per-attempt must be supplied once E2/E5 give one, or left as the labelled ESTIMATE below.
"""
import argparse

# --- current firmware placeholders (firmware/src/field_node/main.cpp, sentinel_proto/gate_policy.h) ---
BUDGET_CAPACITY_J = 20.0          # ENERGY_BUDGET_CAPACITY_J -- PLACEHOLDER
REFILL_RATE_J_PER_S = 0.05        # ENERGY_BUDGET_REFILL_J_PER_S -- PLACEHOLDER
HANDSHAKE_COST_J = 0.02           # GatePolicyConfig::handshake_cost_j -- PLACEHOLDER
CHALLENGE_COST_J = 0.0005         # GatePolicyConfig::challenge_cost_j -- PLACEHOLDER

# --- shipped ADAPTIVE pacer defaults (firmware/src/attacker/attacker_pacer.h PacerConfig) ---
PACER_WINDOW_MS = 5000
PACER_MAX_IN_WINDOW = 5

# No measurement of E_rx (energy to receive one HELLO's frames up to the gate decision) exists
# yet. This ESTIMATE scales Table 1's level-3 HELLO frame count (20 frames) by a per-frame
# reception-energy guess; replace with S2's measured "energy per dropped HELLO" when it exists.
HELLO_FRAMES_LEVEL3 = 20
ESTIMATED_RX_MJ_PER_FRAME = 0.05   # ESTIMATED, not measured: order-of-magnitude placeholder only


def budgeted_bound_j(t_s, capacity_j=BUDGET_CAPACITY_J, refill_j_per_s=REFILL_RATE_J_PER_S):
    """Eq. (1): worst-case total energy an attacker can extract through the budget in t_s seconds,
    however the classifier is fooled. Exact for EnergyBudget's actual mechanics (not an approximation)."""
    return capacity_j + refill_j_per_s * t_s


def budgeted_bound_avg_power_mw(t_s, capacity_j=BUDGET_CAPACITY_J, refill_j_per_s=REFILL_RATE_J_PER_S):
    """Eq. (2) in mW."""
    return 1000.0 * budgeted_bound_j(t_s, capacity_j, refill_j_per_s) / t_s


def long_run_budgeted_power_mw(refill_j_per_s=REFILL_RATE_J_PER_S):
    """The T -> infinity limit of (2): long-run drain through the gate is bounded by the refill
    rate alone, independent of the classifier."""
    return 1000.0 * refill_j_per_s


def max_attempt_rate_hz(max_in_window=PACER_MAX_IN_WINDOW, window_ms=PACER_WINDOW_MS):
    """Eq. (3): the attacker's own pacer cap, not a property of the victim."""
    return max_in_window / (window_ms / 1000.0)


def unbudgeted_power_mw(rx_mj_per_attempt, max_in_window=PACER_MAX_IN_WINDOW, window_ms=PACER_WINDOW_MS):
    """Eq. (4)."""
    return max_attempt_rate_hz(max_in_window, window_ms) * rx_mj_per_attempt


def total_worst_case_mw(t_s, rx_mj_per_attempt, capacity_j=BUDGET_CAPACITY_J,
                         refill_j_per_s=REFILL_RATE_J_PER_S, max_in_window=PACER_MAX_IN_WINDOW,
                         window_ms=PACER_WINDOW_MS):
    return (budgeted_bound_avg_power_mw(t_s, capacity_j, refill_j_per_s)
            + unbudgeted_power_mw(rx_mj_per_attempt, max_in_window, window_ms))


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--seconds", type=float, default=3600.0, help="attack duration T (default: 1 hour)")
    ap.add_argument("--rx-mj-per-attempt", type=float,
                     default=HELLO_FRAMES_LEVEL3 * ESTIMATED_RX_MJ_PER_FRAME,
                     help="ESTIMATED unless a measured per-attempt reception energy is supplied")
    ap.add_argument("--capacity-j", type=float, default=BUDGET_CAPACITY_J)
    ap.add_argument("--refill-j-per-s", type=float, default=REFILL_RATE_J_PER_S)
    ap.add_argument("--max-in-window", type=int, default=PACER_MAX_IN_WINDOW)
    ap.add_argument("--window-ms", type=float, default=PACER_WINDOW_MS)
    a = ap.parse_args()

    print("Budgeted bound (Eq. 1-2) -- holds for ANY classifier behaviour, including a fooled one:")
    print(f"  B={a.capacity_j} J, r={a.refill_j_per_s} J/s "
          f"{'(PLACEHOLDER, not yet measured -- task S2)' if (a.capacity_j, a.refill_j_per_s) == (BUDGET_CAPACITY_J, REFILL_RATE_J_PER_S) else ''}")
    for t in sorted({60.0, 600.0, a.seconds, 86400.0}):
        bj = budgeted_bound_j(t, a.capacity_j, a.refill_j_per_s)
        print(f"    T={t:>8.0f} s: total <= {bj:.3f} J  (avg power <= {budgeted_bound_avg_power_mw(t, a.capacity_j, a.refill_j_per_s):.2f} mW)")
    print(f"  long-run (T -> inf): avg power <= {long_run_budgeted_power_mw(a.refill_j_per_s):.2f} mW\n")

    rate = max_attempt_rate_hz(a.max_in_window, a.window_ms)
    print("Unbudgeted bound (Eq. 3-4) -- bounded by the ATTACKER's own pacer, not the victim:")
    print(f"  pacer cap: {a.max_in_window} attempts / {a.window_ms/1000:.1f} s = {rate:.3f} attempts/s")
    print(f"  per-attempt reception cost: {a.rx_mj_per_attempt:.3f} mJ "
          f"{'(ESTIMATED: ' + str(HELLO_FRAMES_LEVEL3) + ' frames x ' + str(ESTIMATED_RX_MJ_PER_FRAME) + ' mJ/frame placeholder -- not measured)' if abs(a.rx_mj_per_attempt - HELLO_FRAMES_LEVEL3 * ESTIMATED_RX_MJ_PER_FRAME) < 1e-9 else ''}")
    print(f"  unbudgeted avg power <= {unbudgeted_power_mw(a.rx_mj_per_attempt, a.max_in_window, a.window_ms):.2f} mW\n")

    total = total_worst_case_mw(a.seconds, a.rx_mj_per_attempt, a.capacity_j, a.refill_j_per_s,
                                a.max_in_window, a.window_ms)
    print(f"Total worst-case average power over T={a.seconds:.0f} s: <= {total:.2f} mW")
    print("\nReplace the PLACEHOLDER/ESTIMATED inputs above once S2 measures handshake_cost_j, "
          "challenge_cost_j and the per-attempt reception energy, and once H measures the real "
          "budget capacity/refill rate on the rig.")


if __name__ == "__main__":
    main()
