# paper/ : data, decisions and notes for the SentinelMesh paper

Everything the paper's numbers come from lives here. Rules (from the execution guide):

1. **Raw only.** Never edit a log by hand. A bad run stays; mark `excluded=y` + reason in `runlog.csv`.
2. **Run IDs:** `E1-2026-10-14-r03` (experiment, date, run number that day) = the folder name under `data/<experiment>/`.
3. **Commit before every session**; record `git rev-parse --short HEAD` in `runlog.csv`.
4. **Label boards:** F1 (field node), GW (gateway), ATK (attacker), MON (monitor), L1/L2 (extra legitimate nodes).
5. **Capture serial with timestamps:** `pio device monitor -b 115200 --filter time --filter log2file`.
6. **Measurement build vs demo build.** During any energy experiment the field node is a *bare ESP32*: no LCD, LEDs, buzzer or sensors (they draw current and would be counted as crypto cost).

| File | Purpose | Status |
|---|---|---|
| `decisions.md` | Phase 1 design decisions | TO FILL (team) |
| `setup.md` | Exact hardware, software versions, calibration | TO FILL (team) |
| `runlog.csv` | One row per run | header only |
| `protocol.md` | Final handshake formats, budget numbers (Phase 6) | not started |
| `data/E0/` | PQC bring-up logs (+ `HOST_TEST.md`) | host test done; ESP32 log pending |
| `photos/` | Rig and layout photos | pending |
| `analysis/` | Scripts that rebuild every table/figure from raw data | pending |
