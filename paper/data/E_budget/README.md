# E_budget: does the joule budget bind? (2026-10-27 evening, 3 runs)
Boards on USB, **no INA219** (this measures the budget's behaviour, not power). F = `field_node_bench` with FEAT rows
(prints `budget_j` every second), G = `gateway`, A = attacker from `paper/analysis-writing` 76692eb.
Each run: 60 s baseline, 30 s gate v2 settle, **600 s FORGE + ECHO at 5/s**, 60 s recovery
(`paper/tools/session_2026-10-27_evening.sh`). Placeholder budget B = 20 J, r = 0.05 J/s, c_h = 0.02 J.

| Run | Budget at attack start | Budget empty at | Spend/s before | Spend/s after empty | Drop/s after empty | Echoes (A) |
|---|---|---|---|---|---|---|
| rep1 | 20.0 J | +537 s | 4.52 | **2.48** | 2.20 | 151 |
| rep2 | 8.6 J | +235 s | 4.13 | **2.49** | 1.79 | 151 |
| rep3 | 8.6 J | +260 s | 4.10 | **2.49** | 2.17 | 150 |

- **The budget binds.** Once empty it stays near 0 and admissions settle at 2.48-2.49 spends/s, which is exactly the
  refill bound r / c_h = 0.05 / 0.02 = 2.5/s; the rest are dropped (rule 3). Rep 1 emptied at +537 s, close to the
  predicted ~500 s from a full bucket.
- **Reps 2-3 started with a part-filled bucket** (8.6 J): 170 s between attacks refills only 8.5 J at 0.05 J/s
  (a full bucket takes 400 s). Not an error, but say so; in the E5 grid, gate runs were ≥10 min apart, so they
  started full.
- The cap is on what F *charges*. A FORGE admit really costs ≈3.45 mJ (E5 marked ops), so after the bucket empties
  the forced work is ≈2.5 x 3.45 ≈ **8.6 mW ESTIMATED** (vs +15-16 mW measured before it empties). Not measured: no
  INA219 on this run.
- A's counters are cumulative across runs; per-run figures above are differences.
