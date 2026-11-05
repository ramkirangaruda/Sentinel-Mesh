# E2: energy per crypto operation (2026-10-26)

F (ESP32-WROOM-32, 240 MHz, PQClean "clean" C, radio OFF) running `benchmark_energy` (BENCH_REPEAT=20, GPIO4 marker
around every op, 20 ms gap), powered only through the calibrated INA219; M logged with `paper/tools/capture.py`.

- `*_benchmark_energy_F_usb_names.log`: the same build on USB (not the rig) to record the op names and order
  (CSV `algo,op,us,heap,stack,ok`). 20 timed ops per round; ML-DSA-87 skipped (does not fit the stack).
- `*_benchmark_energy_rig_M.log`: M on the rig: 400 `monitor,op_N,us,mJ,peak_mA` rows = 20 rounds x 20 ops,
  matched to names by order (counts and durations agree; ML-DSA sign differs because signing time is random
  per run).

Quick look (person H; paper version is task S2). Energy corrected by 1/1.0367 (session-2 calibration). Idle with
the radio off = 225 mW (after the benchmark). Above idle = op energy minus idle power x op duration. Mean over
n = 20 with 95 % CI:

| op | time (ms) | total mJ | above idle mJ |
|---|---|---|---|
| ML-KEM-512 keygen / encaps / decaps | 5.9 / 6.1 / 7.4 | 1.94 / 2.06 / 2.52 | 0.62 / 0.68 / 0.85 |
| ML-KEM-768 keygen / encaps / decaps | 8.6 / 9.7 / 11.5 | 2.91 / 3.27 / 3.93 | 0.98 / 1.10 / 1.34 (±0.03) |
| ML-KEM-1024 keygen / encaps / decaps | 12.8 / 13.9 / 16.6 | 4.41 / 4.76 / 5.69 | 1.53 / 1.63 / 1.97 |
| ML-DSA-44 keygen / sign / verify | 15.4 / 44 / 16.2 | 5.30 / 15.4 / 5.57 | 1.83 / 5.4 ±1.3 / 1.93 |
| ML-DSA-65 keygen / sign / verify | 26.0 / 86 / 26.2 | 9.05 / 30.0 / 9.14 | 3.19 / 10.6 ±4.1 / 3.23 (±0.03) |
| X25519 keygen / shared secret | 458 / 476 | 145 / 150 | 42.2 / 43.3 |
| ECDSA-P256 keygen / sign / verify | 251 / 115 / 265 | 78 / 36 / 82 | 21.4 / 9.9 / 22.7 |

Peak current during crypto ~71 mA (radio off). The classical baselines are much slower here than optimised
implementations would be: check which library the benchmark uses before comparing PQC with classical in the paper
(HANDOFF_3DAY "classical baseline caveat").
