#!/usr/bin/env bash
# Overnight chain for 2026-10-26 (F on the INA219 rig with field_node_energy, G/A/M on USB).
# Each block is one run_e5_grid call; a failed block does not stop the next one.
# usage: bash paper/tools/overnight_2026-10-26.sh COMg COMa COMm
set -u
G=$1; A=$2; M=$3
PY=${PY:-python}
OUT=paper/data/E5_rig
grid() { echo "=== $(date '+%H:%M:%S') start: $*"; "$PY" paper/tools/run_e5_grid.py --g "$G" --a "$A" --m "$M" --out "$OUT" "$@" \
           2>&1 | grep -a "=== run\|Traceback\|rror"; echo "=== $(date '+%H:%M:%S') end (exit ${PIPESTATUS[0]})"; }
# 1. cookie-copying insider: the case that separates cookie from gate (10 runs, ~50 min)
grid --defences cookie gate --attacks INSIDER --echo --reps 5 --tag echo
# 2. Ramkiran's adaptive attackers, E7 (30 runs, ~2.5 h); ADAPTIVE_SPOOF uses random signatures (cheap to reject)
grid --defences none cookie gate --attacks ADAPTIVE ADAPTIVE_SPOOF --reps 5 --tag adaptive
# 3. rate sweep (36 runs, ~3 h)
grid --defences none gate --attacks FLOOD INSIDER --rates 5 20 50 --reps 3 --tag rate
# 4. long slow drip: 30-min attack windows (4 runs, ~2.2 h)
grid --defences none gate --attacks SLOW_DRIP --flood 1800 --reps 2 --tag slowdrip30
echo "=== $(date '+%H:%M:%S') overnight chain done"
