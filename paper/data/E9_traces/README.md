# E9: field-1 traces for retraining EnergyGate (2026-10-27 evening, 18 runs + the 3 E_budget runs)
Boards on USB, no INA219. F = `field_node_bench`, which now prints `FEAT {...}` once a second: its own 8 features in
`FEATURE_ORDER` (sliding 5 x 1 s window), the score `p` of the model it carried (trained on SIMULATED traces), the
defence and the budget. Gate v2 throughout. 6 attacks (FLOOD, INSIDER, SLOW_DRIP, FORGE, ADAPTIVE, ADAPTIVE_SPOOF)
x 3 sessions (rep1-3, run back to back, ~30 min each); each run 150 s normal + 120 s attack.

`python paper/analysis/build_traces.py` writes `traces_field1.csv` (one row per FEAT line, labelled from the
timeline; FORGE_ECHO rows from `../E_budget/`, sessions `budget_1..3`). Rows: normal 3090, transition 208, each
attack ~348, FORGE_ECHO 1788.

What the carried (SIMULATED-trained) model does on these real rows, threshold 0.4 (challenge):

| Label | n | mean p | flagged (p < 0.4) |
|---|---|---|---|
| normal | 3090 | 0.96 | 0.00 |
| FLOOD / INSIDER / FORGE | ~348 each | 0.10 | 1.00 |
| FORGE_ECHO | 1788 | 0.00 | 1.00 |
| SLOW_DRIP | 348 | 0.96 | 0.00 |
| ADAPTIVE / ADAPTIVE_SPOOF | ~348 each | 0.96 / 0.89 | 0.00 |

Caveats for whoever trains on this:
- **Split by session, never randomly**: rows are 1 s apart over a 5 s window, so neighbours overlap.
- **`rssi_mean`/`rssi_var` are 0 when no HELLO arrived in the window** (normal rows average -10 dBm, attack rows
  -37): "0" means missing, not 0 dBm. A model can learn "any HELLO at all = attack" from it. Treat as missing or
  drop it, and report with and without.
- `battery_pct` is a constant 100 (SIMULATED, no cell on this rig): drop it or expect it to carry nothing.
- All under gate v2, so attacker traffic is what it looks like when challenged (e.g. INSIDER is not admitted, so
  `hs_fail` stays 0); FORGE_ECHO is the only case with admitted failing HELLOs (`hs_fail` ≈ 15 per window).
- One rig, one room, one distance (0.05 m): a held-out session is not a held-out environment.
