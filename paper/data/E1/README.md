# E1 — on-device PQC timing (radio off, 240 MHz, PQClean clean C, USB powered)
Raw captures: `board_<MAC>_runN_raw.txt` (terminal transcript incl. build/upload; benchmark CSV starts after `algo,op,us,...`).
Boards: see boards.csv (F,G,A,M). Raw logs in raw/. ML-DSA-87 sign does not fit (largest free heap block 110580 B -> 94196 B stack).
Caveats: heap_used_bytes is 0 (buffers are static); X25519/ECDSA baselines are mbedtls generic C, not an optimised Curve25519, so do not claim PQC beats classical from these.
Need >= 5 runs per board before any number goes in the paper.

## Repeat session, 2026-10-27 (person H)
Same `benchmark` build (BENCH_REPEAT=1) reflashed to all four boards on USB, radio off; 23 resets per board
(`firmware/logs/device-monitor-261027-*-<label>.log`, one complete run each, 92 logs, 0 failures). Each board now
has 5 independent sessions (10-08, 10-12, and three groups on 10-27) and n = 29-30 samples per op.
Run `python paper/analysis/e1_summary.py` to rebuild the summaries.

- Every deterministic op agrees across the four boards to within 0.6 % and with the earlier medians to 0.1 ms.
- ML-DSA signing is rejection-sampled, so per-board medians still move: report the pooled distribution, not a
  single median. Pooled over 4 boards (n = 116): ML-DSA-44 sign median 48.8 ms (p10 24.1, p90 92.4, max 166.6);
  ML-DSA-65 sign median 63.4 ms (p10 37.1, p90 152.7, max 394.8). Median of board medians: 48.8 / 65.4 ms.
