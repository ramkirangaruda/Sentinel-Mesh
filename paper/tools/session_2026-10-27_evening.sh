#!/usr/bin/env bash
# 2026-10-27 evening, boards on USB (no INA219): F=field_node_bench (prints FEAT rows), G=gateway,
# A=attacker from paper/analysis-writing 76692eb. Part 1: does the joule budget bind? Part 2: field-1 traces
# for retraining EnergyGate (paper Section 9, option b).
set -u
PY=~/sentinel-venv/Scripts/python
P="--g COM11 --f COM10 --a COM4"
echo "== part 1: FORGE+ECHO vs gate v2, 10-min attack, 3 reps  $(date)"
$PY paper/tools/run_e5_grid.py $P --defences gate --attacks FORGE --echo --flood 600 --reps 3 \
    --out paper/data/E_budget --tag budget10
echo "== part 2: traces, gate v2, 6 attacks x 3 sessions  $(date)"
$PY paper/tools/run_e5_grid.py $P --defences gate --attacks FLOOD INSIDER SLOW_DRIP FORGE ADAPTIVE ADAPTIVE_SPOOF \
    --reps 3 --out paper/data/E9_traces --tag traces
echo "== done  $(date)"
