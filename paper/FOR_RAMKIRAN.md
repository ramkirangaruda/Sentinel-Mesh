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
1. **Section 9 (S7) traces: DECIDED, option (b), being recorded 2026-10-27 evening.** The E5 gateway logs were
   all labelled `normal` and were the gateway's view, so Chaitanya is recording field-1's own features instead (see
   section 5 below for files and format). No decision needed from you; just use the new data.
2. **Cookie weakness.** Report-only (current text), or fix it (bind the cookie to the HELLO's nonce/(epoch, seq) or
   make it single-use) and rerun FORGE+ECHO? A rerun needs an INA219 again.
3. **10-minute budget run** (item 1.3): **being run 2026-10-27 evening** without an INA219 (3 x FORGE+ECHO vs gate
   v2, 600 s attack). It shows whether the budget empties and admissions fall to the refill rate, from field-1's own
   counters and budget readout; it gives no power numbers. Results in section 5 once done.
4. **Measured costs back into the firmware?** c_h ≈ 15 mJ (handshake, field-1's side), ≈3.5-3.9 mJ (failed verify);
   every run in the paper used the placeholders, which is fine as long as the text says so (it does).

## 4. Still open on Chaitanya's side (for your planning)
- DT830 multimeter vs a calibrated bench meter (Limitations: 3.67 % gain question; ratios unaffected).
- Section 9 traces, if you choose 3.1(b).

## 5. New results, 2026-10-27 evening (boards on USB, no INA219)
**a. The joule budget binds** (`paper/data/E_budget/README.md`; answers item 1.3). 3 x FORGE+ECHO vs gate v2,
600 s attack. The bucket empties (+537 s from full; reps 2-3 started part-filled at 8.6 J and emptied at +235/+260 s)
and admissions then settle at **2.48-2.49 spends/s = r/c_h = 2.5/s**, the rest dropped by rule 3. So in Section 8
replace "not tested / a 10-minute run would be needed" with this. Be precise: it caps what F *charges*; the real
work it still lets through is ≈2.5 x 3.45 mJ ≈ **8.6 mW, ESTIMATED** (no power measured on this run), down from
+15-16 mW measured before the bucket empties.

**b. Section 9 data is ready** (`paper/data/E9_traces/README.md`; `python paper/analysis/build_traces.py` ->
`traces_field1.csv`). Field-1's own 8 features + the carried model's score, once a second, labelled from the run
timelines: 6 attacks x 3 sessions + 3 FORGE_ECHO sessions, ~7,800 rows. Please:
- split by `session` (never random); report AUC and TPR at 1 % FPR, next to the SIMULATED-trained model and a
  hand-tuned threshold rule (the S7 plan);
- baseline already visible: the SIMULATED-trained model flags FLOOD/INSIDER/FORGE/FORGE_ECHO 100 % with 0 false
  alarms on normal rows, and misses SLOW_DRIP, ADAPTIVE and ADAPTIVE_SPOOF entirely (they stay under its rate cue).
  That miss is the honest headline for "the classifier is evadable, the budget is the guarantee" (C3);
- **watch the RSSI leak**: `rssi_mean`/`rssi_var` are 0 when no HELLO arrived, so "0" means missing. Report with and
  without those features; `battery_pct` is a constant 100 (SIMULATED), drop it.
- Firmware change behind it: `firmware/src/field_node/main.cpp` bench build prints `FEAT` rows (commit on
  `paper/e5-grid-tooling`); energy builds are unchanged.
