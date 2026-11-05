# For Ramkiran: open items from Chaitanya's side (running list, started 2026-10-27)

Merge `origin/paper/e5-grid-tooling` first: it has all the rig data, the E1 repeats and this file.
Everything below was checked against the raw data in `paper/data/` and `paper/CONTEXT_2026-10-24.md`.

## 1. Fixes to `paper/writing/paper.md` from the review of 76692eb
**Status 2026-10-28: items 1-6 done in your 038f7e0, thanks.** Item 7 is still open (038f7e0 has the line too).
Section 8 now says the bound is "derived, not demonstrated"; section 5a below makes it demonstrated, so update it.

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

## 6. Review of be0b2da and 3647f2e (2026-10-30)
**Checked and fine:** Table 2 matches E1; the budget paragraph matches `E_budget`; `train_energygate_real.py` reruns to
the committed metrics exactly; 359/359 native tests pass.

**Blocker: the cookie fix locks the real gateway out. Do not flash 3647f2e for a rerun yet.**
- `transmit_hello()` in `firmware/src/gateway/main.cpp` takes a fresh seq on every send, including the cookie retry. The
  cookie is now bound to the challenged seq, so the retry fails, gets a new challenge, and repeats. `decisions.md` #5
  says the same signed HELLO is resent; it does not say the same header. Section 10's "resends the same header
  unmodified" is therefore wrong for the code as built.
- Expected on the rig (from the code and a host replay of the cookie class; not yet run on boards): under COOKIE the
  gateway never completes a handshake, even with no attack; under GATE v2 it fails whenever its score is low. Each retry
  also resets `g_att.deadline_ms`, so it may never time out. The new cookie tests pass because they test the class, not
  the gateway.
- The attacker has the same flaw: its echo also takes `g_epoch++, g_seq++` (`firmware/src/attacker/main.cpp`), so a rerun
  as it stands would show the attack "stopped" only because this attacker echoes wrongly. A real one echoes under the
  challenged (epoch, seq) and gets admitted, for one round trip (it can trigger the challenge with fragment 0 alone).
  So "closing FORGE+ECHO's reuse" is right about reuse, but the attack is made dearer, not closed. Say that in Sections
  8 and 10.
- Needed before the rerun: the gateway keeps its (epoch, seq) on a cookie retry; the attacker gets a same-seq echo.
  Rerun all three: no attack, old echo, same-seq echo. Report legit success as well as power.

**Section 9, last paragraph:** the bucket does not stand between SLOW_DRIP and exhaustion. 1 HELLO/min charges
0.02 J / 60 s ≈ 0.33 mW against a 50 mW refill, so it never binds. SLOW_DRIP is harmless because its drain is tiny
(+0.2 mW, Table 6), not because of the budget. Keep "the score can't see it", drop the budget claim.

**Smaller fixes**
- Section 6.1 calls 394.8 ms the "true worst case": rejection sampling has no fixed maximum, so say "largest observed".
  Sections 5 and 7 also quote 80-560 ms, which is whole-handshake time, as signing time.
- Section 8: "bound (1)-(2)" has no numbered equations; "Section 5's FORGE+ECHO arithmetic" is not in Section 5; the
  +15-16 mW comes from the FORGE+ECHO table, not Table 6.
- Section 10's "Model trained on SIMULATED traces ... until it is retrained" is out of date: the retrain is done, but
  the firmware still carries the old model. Say that.
- Item 1.7: all three new commits still have `Co-Authored-By`.

**Still open from earlier:** attacker energy and the C2 ratio; Figures 1 and 2.

**Two drafts are diverging.** `paper/ieee/paper.tex` (on `paper/e5-grid-tooling`, not in your branch) has the abstract,
related work, conclusion and references, which are still empty in `paper.md`, but not your Section 9 baseline or the
cookie fix. Title and authors differ too. Pick one file as the source. Also pick one TPR method: 0.754 (interpolated,
yours) against 0.751 (`e9_retrain.py`) for the carried model.

**Update, 2026-10-30: blocker fixed in firmware.** Your branch is merged into `paper/e5-grid-tooling`. The gateway keeps
its (epoch, seq) on a cookie retry; the attacker has `ECHO same` (the old `ECHO on` stays, to reproduce the earlier runs).
Merge this branch before touching the firmware. Section 10's "resends the same header" is now true.

## 7. Cookie rerun results, 2026-10-31 (INA219 rig, firmware 7afdea4, 53 runs)
All from `paper/data/E_cookie_fix/README.md`; rebuild with `python paper/analysis/cookie_fix_summary.py`. Use these in
Sections 8 and 10, and in the `paper/ieee/paper.tex` text that says the fix is pending.
- **No attack:** the real gateway succeeds 128/132, so the fix does not lock it out.
- **No defence, for reference:** FORGE gives +14.7 ± 0.9 mW at 4.97 verifies/s, so a forced verify costs about 3 mJ.
- **Cookie against non-echoing or fresh-seq attackers:** stopped, within about 1 mW of idle.
- **Cookie against a same-seq echo:** not stopped. 900 s: +13.0 ± 1.0 mW at 4.71 admits/s, about 12 % below no defence. The
  attacker pays one echo per HELLO (about 4.6/s, roughly double the frames). **Write "makes the attack dearer", not "closes it",**
  and say the victim saves little.
- **The budget's effect is now measured (Section 8):** same attack under gate v2, 900 s, n = 3. The bucket empties at
  +633/+412/+415 s, admissions hold at 2.42/s (bound 2.5/s), extra power falls from +12.2 ± 4.3 to **+5.5 ± 2.4 mW**, while
  cookie stays flat at +13.0. Replace the 8.6 mW ESTIMATED. The runs were about 3.5 h apart, not interleaved.
- **Availability, which the paper must say:** real gateway 97 % with no attack, 49 % at 100 frames/s (the same with F verifying
  every HELLO or none), 8-21 % with echoes. So the loss follows radio load, not F's crypto; frame loss is the likely mechanism but
  was not measured directly. The defences protect energy, not availability. It recovers within a minute of the attack stopping.
- **Noise:** the 120 s same-seq runs (+7 mW) fall in a noisy stretch, cause unknown. Use the 900 s figures. The 900 s no-attack
  control reads +0.2 ± 0.4 mW.

**Decision needed, c_h and r:** the cap binds here only because c_h = 20 mJ is about 7x a real forced verify (about 3 mJ). With an
honest 3 mJ and r = 50 mW the cap is 16.7 admits/s, and a 5/s attacker never empties the bucket. Either say the placeholders are what
make it bind, or set r from a target battery life and rerun. Also fix item 3.4's "failed verify 3.5-3.9 mJ" if you quote this figure.

## 8. Review of cb87a32 and 6bbd8ab (2026-11-01)
**Checked and fine:** the rerun numbers match `E_cookie_fix`, `e9_retrain.py` reproduces Table e9 exactly, Figure 2 uses corrected
`power_mw`, and `paper.tex` builds to 6 pages with no errors or undefined references. `paper.pdf` is still the 10-29 one: rebuild it
after these fixes (pdflatex is on Chaitanya's laptop if you need it).

**Wrong, fix in `paper.tex`:**
1. **Abstract:** "+13.0 mW under a cookie ... down from an unbound cookie's +16.0". +16.0 was gate v2; the cookie figure is +15.1.
   It also compares across days, so say that or drop the comparison.
2. **Table `tab:cookiefix`:** the +0.2 ± 0.4 control was **gate v2**, not "none". Its caption "(except control)" is wrong too, as the
   control was also on the INA219. The table is 88 pt too wide and runs into the next column.
3. **Echo rate:** "≈4.7 s⁻¹" is the admit rate. Echoes were 4.6/s.
4. **"both recover within the attack's last minute once it stops":** should say the gateway reconnected within a minute after the attack stopped.
5. **Figure/table mismatch:** the 900 s paragraph cites `fig:budget` and `tab:budget`, which show the older 600 s USB runs on the reusable
   cookie. Add the 900 s per-rep table from `E_cookie_fix/README.md`, and cite those two only for the 600 s sentence.
6. **"the budget is the guarantee" (end of the traces section) and "does not depend on being right" (Conclusion):** these contradict your
   own, correct placeholder paragraph. The cap on charges always holds; the cut in real drain shown here depends on c_h overcharging.
   Reword both, and add the same caveat to C3 in the Introduction.

**Needs a sentence, numbers disagree across sessions:**
7. FORGE, no defence: **+19.0** (Table e5, abstract) against **+14.7** (rerun). Forced verify: **3.45-3.5 mJ** (marked) against **≈3 mJ**
   (mean power / rate). The 7x overcharge uses 3 mJ; it is 5.8x with 3.45. Say these are two sessions and two methods.
8. Legit success, FORGE: **0.23-0.28** (Table e5) against **42-58 %** (rerun), and idle 598 mW against 578 mW corrected. The boards were
   placed differently, and the 3 % idle shift is unexplained. Say absolute values do not carry across sessions, and compare within a session.
9. **Table e5 was on earlier firmware.** Field-1's only functional change since is the cookie binding, so non-echo energy results stand
   (no-echo FORGE was rerun and agrees), but state the firmware for each table. Likewise the Section 9 traces predate the bound cookie and
   contain no same-seq echo; add that to Limitations.

**Unsupported claim:**
10. **"It removes the insider drain (+1.1 mW)" holds only for a non-echoing insider.** The threat model says "+ECHO: any of the above", yet
    all 10 INSIDER+ECHO runs are excluded because no echo was ever sent, and FORGE now shows a same-seq echo gets admitted. Qualify the abstract
    and findings now. A rerun is proposed; results would go here.

**Smaller:**
11. **Multimeter:** the calibrated-meter check will not happen. Delete `[TODO H: ...]` in `paper.md` and the "Still open" line in section 4 above. In
    Setup, say the reference is a hobby DT830D, not a calibrated meter, and add the bus-voltage systematic (INA219 reads 1.4-3.1 % above the
    DT830D), which `paper.tex` omits.
12. **Figure 1:** "needs oscilloscope-rate sampling" overstates it. M samples at about 989/s, plenty for a 400 ms handshake; it was just not logged sample by sample.
13. **Limitations:** "the ratio C2 actually claims" does not match C2 as written in the Introduction, which claims no ratio. Align them.
14. **Citations:** matching keys does not show the papers exist or say what we claim. A quick search confirmed `leetls`' title, ID and 88x finding but
    not its authors, and found `gillot2` only through press coverage. It did not find `karcz` or `gillot1`; that is not proof they are absent. Open all four.
15. `paper.tex`'s header comment still says it is built from `paper.md`, reversing the canonical decision. Both new commits keep `Co-Authored-By`.

## 9. Insider echo results, 2026-11-01/02 (INA219 rig, 21 runs + 2 excluded smokes)
Full tables: `paper/data/E_insider_echo/README.md`. F and G at 7afdea4, A at 389d74f. **This changes the abstract's main claim, so read it first.**

Every earlier INSIDER+ECHO run was excluded because the attacker's echoes never fired, so the threat model listed a case nobody had tested. Now they fire (about 2,700 per 600 s run):

| Defence | Attack | Window | n | Extra F power | Admits/s | Drops |
|---|---|---|---|---|---|---|
| none | insider | 600 s | 3 | +73.2 ± 4.1 mW | 2.38 | 0 |
| cookie | insider + echo | 600 s | 3 | +58.5 ± 13.7 mW | 2.03 | 0 |
| gate v2 | insider + echo | 600 s | 3 | +69.0 ± 9.4 mW | 2.26 | 0 |
| cookie | insider, no echo | 120 s | 3 | +2.8 ± 1.0 mW | 0.04 | 0 |
| gate v2 | insider, no echo | 120 s | 3 | +2.4 ± 1.5 mW | 0.08 | 0 |

**What has to change in `paper.tex`:**
1. **Abstract, "It removes the insider drain (+1.1 mW)":** true only for an insider that does not echo. An insider that echoes gets through gate v2 at about the undefended drain, and the intervals overlap. A key-holding insider can read a broadcast cookie, so the echoing case is the one the threat model should expect. Also update +1.1 to the current firmware's +2.4 ± 1.5 (with cookie alone at +2.8 ± 1.0, so the gate adds nothing over the cookie here).
2. **"The budget is the guarantee":** it is not, against this attacker. No drops in 3 runs, and `budget_j` never fell below 19.26 of 20 J. The crypto slot holds admits to about 2.26/s, which charges 45 mW against a 50 mW refill, so the 2.5/s cap is never reached. Real cost is about 30 mJ per admit against the 20 mJ charged. This also settles section 8's budget contradiction: the budget bounds only attackers fast enough to reach the cap, and it binds on FORGE only because c_h overcharges a forged verify.
3. **Contributions and Conclusion:** state plainly that EnergyGate does not stop an authenticated insider who echoes. That needs a different control (per-peer limits or revoking the key), which this paper does not build or test. Do not imply it does.
4. **Cookie vs gate, 900 s, now paired in one session:** cookie +19.7 ± 0.9 mW; gate about +18 mW until the bucket empties (+438 to +466 s), then about +9 mW. Gateway 23/185 vs 31/189. Use these in place of the 3.5 h apart comparison, or at least alongside it.
5. **Do not mix sessions.** The same cookie cell gave +13.0 ± 1.0 mW on 10-31 and +19.7 ± 0.9 mW now, with the same F firmware. Idle and RSSI moved too, but the boards were not moved, and the cause is not established. The abstract's +13.0 is affected; section 10 has the repeat. Add this to Limitations and compare only within a session. Likewise +73.2 here is not the paper's +91.2 (fresh signature, 120 s, earlier session).

**Your call, c_h:** charging the measured 30 mJ would cap admits at about 1.6/s (about 50 mW) and empty the bucket in about 1,000 s under this insider. That is ESTIMATED and has no firmware test behind it. Report it only as future work unless we rerun it.

The multimeter item is closed: see section 8 item 11, and the line in section 4 is removed.

## 10. Repeat of the numbers that moved, 2026-11-02 (`paper/data/E_repeat/README.md`)
Same F and G firmware, boards not moved.

| Cell | 10-31 | 11-02 night | 11-02 day |
|---|---|---|---|
| none, FORGE, 120 s | +14.7 ± 0.9 | not run | +14.1 ± 2.2 |
| cookie, FORGE echo, 900 s | +13.0 ± 1.0 | +19.7 ± 0.9 | +9.7 ± 3.1 |

1. **The forger number is solid:** +14.7 and +14.1 agree. Use +14.7 ± 0.9 (or either with its session) and drop +19.0, which predates the bound cookie.
2. **Replace the abstract's "+13.0 mW under a cookie" with the range:** a same-seq echo under a cookie drains about +10 to +20 mW across three sessions at about 4.6 admits/s. Do not quote one value, and do not say the cookie makes this cheaper or dearer than no defence: it was below the forger's figure on 10-31 and in today's session (+9.7 vs +14.1 mW), and +19.7 is above every forger figure we have, though no forger run was made that night.
3. **Add to Limitations:** echo power varied by about 2x across sessions, with F and G firmware unchanged and the boards not moved. **Do not say it rises with RSSI:** the controlled test in section 11 did not support that. Use the wording in section 11.
4. **Section 9's insider results and paired comparison stand,** as within-session results. Their conclusions do not rest on a single absolute mW: +69 mW is far from +1.1 in any session, and gate's drop after emptying is within one session.

## 11. Controlled signal test, 2026-11-02 evening (`paper/data/E_rssi/README.md`)
Cookie, FORGE echo, 300 s, 9 runs. Only A moved, by hand: close, 20 cm and 40 cm, 3 runs each. This replaces the RSSI statement in section 10.

| A at | RSSI at G | Extra power | At fixed 4.85 V | Spend/s | Real gateway |
|---|---|---|---|---|---|
| close | -35 | +14.7 ± 22.3 mW | +13.2 ± 10.4 mW | 4.55 | 11/60, 18 % |
| 20 cm | -42 | +9.4 ± 1.2 mW | +9.5 ± 2.4 mW | 3.83 | 10/59, 17 % |
| 40 cm | -51 | +11.3 ± 26.4 mW | +15.1 ± 8.4 mW | 4.36 | 25/51, 49 % |

1. **Moving A did not make power follow signal:** r = -0.25 between RSSI and extra power, -0.60 at fixed voltage, n = 9. The earlier r = 0.89 is mostly three session clusters. The strongest signal here was -24, so the -16 night's condition was not reproduced and is not ruled out.
2. **F draws a nearly fixed current (117.4-120.0 mA) while its supply moved over 4.75-4.93 V,** so its power follows the supply. A shift during a run reads as extra power: run 7 reads -0.2 mW because the bus fell 0.095 V, though current rose 2.37 mA. Over these 9 runs, using extra current at a fixed voltage halves the spread (SD 7.3 to 3.7 mW).
3. **That does not explain the gap between sessions.** The 900 s runs had almost no shift and still read +14.0, +20.5 and +10.9 mW at fixed voltage. Say this plainly in Limitations: "Extra power under the echo varied about 2x across sessions with firmware and placement unchanged. A controlled test ruled out signal strength as a simple cause over -24 to -53 dBm. Supply voltage shifts explain some within-session spread but not the between-session gap, whose cause is unknown."
4. **Report supply voltage in the method.** The adaptor rig's bus is not fixed, and bus shift should be checked for any single number. Long-window means with a small shift, including the +10 to +20 mW range and +14.7 mW forger figure, are not changed by this.
5. **Insider figures sag:** in section 9's echoing insider runs the bus fell about 0.05 V under load, so measured +73 and +69 mW would be roughly 6-10 mW higher at a fixed voltage (ESTIMATED from those runs, not a rerun). Keep the measured figures. The conclusions do not change.
6. **New, usable result:** the real gateway got through 49 % of the time with A at 40 cm against 17-18 % nearer, while F still spent at 4.36/s. So an attacker further from the gateway still drains F but hurts the gateway less. n = 3 per spot, and A to F signal was not measured.
7. **Caveats to carry:** spots were placed by hand and the close spot read -24 to -44 dBm. The 20 cm runs all came late, so time may confound them. "At fixed 4.85 V" is a derived comparison figure, not a measurement.

## 12. Done for you in `paper.tex`, 2026-11-06 (Chaitanya's session)
Sections 8-11 above are applied to `paper/ieee/paper.tex`, and `paper.pdf` is rebuilt (7 pages, no warnings, no overfull boxes). **Please read the
new PDF; nothing is left for you to write unless you disagree with a choice below.**
- **Abstract** rewritten: forger +14.7 ± 0.9 (repeated), insider +91.2; the gate stops attackers that neither echo nor fool the score; the forger's
  echo under cookie is a +10 to +20 mW range; the echoing insider is not stopped (+69.0 vs +73.2); the budget caps charges, not drain.
- **C3, the insider and the Conclusion** now say the echoing insider is not stopped and the budget's cut in drain depends on c_h overcharging (8.6, 9.2-9.3).
- **Results:** Table IV states its firmware and that absolute values don't carry across sessions (8.7-8.9). The cookie table is rebuilt (control
  is gate v2, fits the column; 8.2). There is a new cross-session echo table with the paired 1-2 Nov gate runs (8.5, 9.4, 10.2) and a new insider table
  (9.1). Echo rate 4.6/s (8.3), recovery wording (8.4), the RSSI gateway result (11.6) and the insider supply sag, marked ESTIMATED (11.5).
- **Setup:** DT830D called a hobby meter, plus the bus-voltage systematic (8.11) and a supply paragraph (11.4).
- **Limitations** rewritten: echo power doesn't repeat, with section 11's wording (10.3, 11.3), placeholder budget both ways, no defence against
  an echoing insider, Figure 1 wording (8.12), C2 ratio aligned (8.13), and firmware per table (8.9).
- **Your c_h decision, taken as the default:** placeholders kept and the 30 mJ charge reported as ESTIMATED future work. Tell us if you'd rather rerun it.
- **Citations (8.14):** `gillot1` (Cryptography 10(4) art. 55, doi 10.3390/cryptography10040055), `gillot2` (arXiv:2610.27766, QSIoT 2026) and
  `leetls` (arXiv:2607.12504; authors Lin-Fa Lee, Yi-Yu Chang, Chia-Mu Yu, Kuo-Hui Yeh) are confirmed and now have full author names. **`karcz` could not
  be found** on PLOS ONE or anywhere else we could search, so it and its sentence are removed. Add it back only with a DOI.
- The header comment now names `paper.tex` as canonical (8.15). The `[TODO H]` meter line in `paper.md` is gone (8.11).
