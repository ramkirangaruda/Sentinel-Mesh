# Work split: two people, two Claude sessions (written 2026-10-24)

The remaining paper work is split so the two people never touch the same files and never wait on each other.
**Person H** has the hardware (all four boards, INA219 rig, multimeter). **Person S** has no hardware and works on
software, analysis and writing. Each person's Claude reads this file, `CLAUDE.md`, `paper/HANDOFF_3DAY.md`,
`paper/GUIDE_FROM_ZERO.md` and `paper/setup.md` first.

## Git: how not to collide
- Base branch: `paper/e5-grid-tooling`. **H** keeps working on it. **S** makes a new branch from it:
  `git fetch && git checkout -b paper/analysis-writing origin/paper/e5-grid-tooling`.
- **Files each person owns** (only the owner edits them; the other may read):

| Owner | Files |
|---|---|
| **H** | `paper/setup.md`, `paper/runlog.csv`, `paper/data/**` (raw logs, never edited), `paper/tools/**`, `paper/GUIDE_FROM_ZERO.md` |
| **S** | `paper/analysis/**` (new scripts), `paper/writing/**` (new: paper text, figures, related work), `firmware/src/attacker/**` (only for task S5) |

- `paper/analysis/e5_summary.py` and `calibration_fit.py` already exist: S owns them from now on; H only runs them.
- S pulls H's branch whenever H says new data landed: `git merge origin/paper/e5-grid-tooling` (no conflicts,
  because the files do not overlap). At the end, both branches merge into `master` by one PR each.

## Person H (hardware), in order
1. **Wire F into the rig** (GUIDE step 1.7): F VIN/GND into the breadboard's +/− columns (after the INA219), marker
   F D4 → 1 kΩ → M D4. Adaptor off while wiring; F's USB never plugged in while on the rig.
2. **First rig check:** G on USB, adaptor on, M logging. Confirm M prints `NRG {...}` lines every second and
   `monitor,op_N,us,mJ,peak_mA` rows when F handshakes. Save the log under `paper/data/E_rig/`.
3. **E2, crypto energy per operation:** flash F with `benchmark_energy` (on USB), move it back to the rig, log M until
   the benchmark finishes. Then one extra run of `benchmark_energy` on plain USB (or through the CP2102 module) to
   capture its CSV, so S can match M's `op_N` rows to operation names.
4. **Handshake, challenge and drop energy:** `field_node_energy` on F, G on USB, M logging; 5 min idle-with-handshakes,
   then a short flood (`run_flood_test.py --g .. --a .. --m .. --defence gate`, no `--f`).
5. **E5 grid with energy:** `run_e5_grid.py --g .. --a .. --m .. --reps 1` (smoke), then `--reps 5`; then the rate
   sweep and the ECHO grid (commands in GUIDE step 2.3). Mark bad runs `excluded=y` in `runlog.csv`.
6. **Reference check (half an hour):** borrow a good bench multimeter (college lab) and measure L1 and L6 once more
   (`setup.md`, "Which instrument is right is not settled").
7. After every session: commit raw logs + `runlog.csv` rows, push, and tell S "new data in `paper/data/...`".

## Person S (software/writing), in any order
Every script goes in `paper/analysis/`, reads only raw files from `paper/data/`, and prints or writes tables;
nothing edits raw data. Test each script on the existing logs or a small hand-made sample until real data arrives.

**S1. Energy parser + calibration correction.** A module (e.g. `paper/analysis/energy.py`) that reads M's log
lines: `NRG {"ts","power_mw","volts","amps","battery_pct"}` (once per second) and `monitor,op_N,us,mJ,peak_current_mA`
(one per marked operation; formats in `firmware/src/monitor/main.cpp` lines ~99-130 and ~235). Apply the INA219
correction from `setup.md` (`I_true = (I_raw + 0.428 mA) / 1.0367`; energy scales the same way) and report the
uncertainty (±0.6 % over 57-232 mA, ±0.2 mA below 20 mA).

**S2. E2 table.** Match `monitor,op_N` rows to the benchmark's CSV (`algo,op,us,heap_used_bytes,stack_hwm_bytes,ok`,
`firmware/src/benchmark/main.cpp`; the order is fixed and each op repeats `BENCH_REPEAT=20` times) and build the
per-operation energy table: mean, sd, 95 % CI, energy minus idle baseline (idle = the 10 s before the first marker).

**S3. E5 energy summary.** Extend `e5_summary.py`: victim joules during the attack window from M's NRG lines (and per
forged HELLO = window energy above baseline / forged HELLOs from G's `LOG field1` counters), legit success with
95 % CI (already there), and an **attacker energy estimate from airtime** (frames sent × airtime × ESP32 TX power,
with the assumption written down; label it ESTIMATED until E3 hardware exists). Output: victim J per attacker J per
defence × attack cell.

**S4. Literature review and related work.** Systematic search (IEEE Xplore, ACM DL, IACR ePrint, Google Scholar,
arXiv) for: PQC energy on microcontrollers; handshake/DoS exhaustion with PQC; battery-exhaustion DoS defences in
IoT; client puzzles/cookies over broadcast radio; learned admission control. A related-work table (paper, platform,
what they measured, what they leave open) in `paper/writing/related_work.md`, positioned against Gillot et al. 2026,
the ESP32-C6 PLOS ONE 2026 paper, Lee et al. 2026 (arXiv) and Hristozov et al. Never claim "first" without it.

**S5. Adaptive attacker (E7), firmware, host-tested only.** A new attacker mode that knows EnergyGate's 8 features
(`ml/sentinel_ml/energygate.py` `FEATURE_ORDER`) and keeps `hs_fail` and `dup_pct` low, spoofs the gateway's id and
paces itself to stay under the score threshold. Edit only `firmware/src/attacker/`; add native tests if logic is
portable; build with `pio run -e attacker`. H flashes and runs it later. The paper's claim: even when the classifier
is fooled, worst-case drain is bounded by the joule budget's refill rate. Compute that bound analytically too.

**S6. Paper skeleton and the sections that need no new data.** In `paper/writing/` (LaTeX or Markdown, team's
choice): title, abstract placeholder, introduction, threat model (attacker in radio range, no keys, can spoof and
replay, knows the defence; out of scope: jamming, physical capture, side channels), system and handshake
(`firmware/lib/sentinel_pqc`, HELLO/RESPONSE/CONFIRM sizes, 20+19 fragments), EnergyGate design (score + joule bucket +
spend/challenge/drop, policy v2 vs v1), measurement rig and calibration (from `setup.md`), and a limitations list
(`HANDOFF_3DAY.md` sections 2 and 6). Results sections get filled from S2/S3 tables when data lands.

**S7 (after H's E5 runs). Retrain EnergyGate on recorded traces.** Use the real G/F logs, split by recording session
(never random), report AUC and TPR at 1 % FPR next to the simulated-trace model, and compare with a hand-tuned
threshold rule. The `ml/` folder owns training code (`ml/train_energygate.py`); keep new training code there.

## Rules both sessions follow
- Honest numbers only; anything simulated or estimated is labelled SIMULATED / ESTIMATED.
- Never edit a raw log; a bad run stays and is marked `excluded=y`.
- Use `127.0.0.1`, never `localhost`.
- Pull before starting each session; push at the end; tell the other person what landed.
