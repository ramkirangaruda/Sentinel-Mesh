# For Ramkiran: open items from Chaitanya's side (running list, started 2026-10-27)

Merge `origin/paper/e5-grid-tooling` first: it has all the rig data, the E1 repeats and this file.
Everything below was checked against the raw data in `paper/data/` and `paper/CONTEXT_2026-10-24.md`.

## 1. Fixes to `paper/writing/paper.md` from the review of 76692eb
Firmware retry in `tick_forge()` is fine; Table 6 and the FORGE+ECHO table match the data exactly.

1. **Handshake crypto sum is wrong (Sections 5, 7, 10).** "≈20.3 mJ" adds ML-DSA-65 keygen (3.19) instead of
   ML-KEM-768 keygen (0.98), and ML-KEM-1024 decaps (1.97) instead of ML-KEM-768 encaps (1.10). Correct, from Table 4:
   - field-1's side (verify HELLO + encaps + sign RESPONSE) = 3.23 + 1.10 + 10.6 ≈ **14.9 mJ**;
   - both sides (keygen + encaps + decaps + 2 signs + 2 verifies) ≈ **31 mJ**.
   So the placeholder *c_h* = 20 mJ is ~1.3x field-1's real crypto cost, not "≈ measured 20.3 mJ". Section 5 already
   says ~15 mJ, so the paper currently contradicts itself.
2. **Table references.** Sections 3 and 5 cite "Table 2: 26.2 ms, 3.2 mJ" / "Table 2 ... about 15 mJ". Table 2 is
   timings only; energy is **Table 4**.
3. **Budget bound is not tested; say so (Section 8).** "ADAPTIVE +25.5 mW is consistent with the ≈51 mW bound" is
   vacuous over 120 s: the bucket starts full (*B* = 20 J), so it never ran low. The bound also caps what field-1
   *charges* (c_h per admit), not real drain; it caps real drain only if c_h ≥ the true cost, and a mesh handshake
   measured up to 65 mJ against a 20 mJ charge. FORGE+ECHO charges ~540 x 0.02 J = 10.8 J per 120 s (≈90 mW against a
   50 mW refill), so the bucket would empty after roughly 8 minutes: a ≥10-minute run is what would test it.
4. **c_c:** give an upper bound instead of "below resolution": ≲2 mW x 120 s / ~600 challenges ≈ **≤0.4 mJ per
   challenge**.
5. **Table 6 caption** "(SLOW_DRIP ≈1/min) over the minute before" is garbled; reword.
6. **Still missing from the old S3 TODO; list as to-do, don't drop silently:** attacker energy (ESTIMATED from airtime;
   no second monitor), the victim/attacker ratio for claim C2, Figure 1 (handshake current trace) and Figure 2 (power
   over time per defence; can be made from `paper/data/E5_rig/` M logs, `power_mw` only).
7. Commit messages: drop the `Co-Authored-By:` line if the team doesn't want them.

## 2. Table 2 (E1) can now be finalised
E1 repeats are pushed (`b252825`; `paper/data/E1/README.md`; rebuild with `python paper/analysis/e1_summary.py`).
Each board has 5 sessions (10-08, 10-12, three on 10-27), n = 29-30 per op, 92 new runs, 0 failures.
- Keep the deterministic rows: all four boards agree within 0.6 % and with the old medians to 0.1 ms.
- Replace the signing cells with the pooled distribution (n = 116; signing is rejection-sampled, single medians move):
  - ML-DSA-44 sign: median **48.8 ms** (p10 24.1, p90 92.4, max 166.6)   [was 57.67]
  - ML-DSA-65 sign: median **63.4 ms** (p10 37.1, p90 152.7, max 394.8) [was 63.24]
- Remove "[TODO: E1 needs at least five runs per board before Table 2 is final.]"
- The "38-287 ms" signing range quoted near Table 4 should match these (or say where it comes from).

## 3. Decisions needed from you
1. **Section 9 (S7) traces.** The E5 gateway logs contain 5 s feature windows, but every one is labelled `normal` and
   they are the *gateway's* view; EnergyGate runs on field-1. Either (a) you label windows from each run's timeline
   (attack on/off times are in `*_timeline.txt`) and accept the gateway-side features, or (b) Chaitanya records
   field-1's own windows on the boards (no INA219 needed, ~1-2 h). Tell him which.
2. **Cookie weakness.** Report-only (current text), or fix it (bind the cookie to the HELLO's nonce/(epoch, seq) or
   make it single-use) and rerun FORGE+ECHO? A rerun needs an INA219 again.
3. **10-minute budget run** (item 1.3): worth borrowing an INA219 again for, or state "not tested" in Limitations?
4. **Measured costs back into the firmware?** c_h ≈ 15 mJ (handshake, field-1's side), ≈3.5-3.9 mJ (failed verify);
   every run in the paper used the placeholders, which is fine as long as the text says so (it does).

## 4. Still open on Chaitanya's side (for your planning)
- DT830 multimeter vs a calibrated bench meter (Limitations: 3.67 % gain question; ratios unaffected).
- Section 9 traces, if you choose 3.1(b).
