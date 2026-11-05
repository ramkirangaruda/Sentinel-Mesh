#!/usr/bin/env bash
# Controlled test: does echo power follow A's signal strength? One run per call, because A is moved by hand between runs.
# Only A moves, along one line away from F and G, same orientation. Cookie, FORGE same-seq echo, 300 s. About 8 min per run.
# Order, a Latin square so placement is not confounded with time: mid far near / far near mid / near mid far
# usage: bash paper/tools/session_rssi_test.sh near|mid|far COMg COMa COMm
set -u
POS=$1; G=$2; A=$3; M=$4
OUT=paper/data/E_rssi
mkdir -p "$OUT"
export PYTHONIOENCODING=utf-8
{ echo "=== $(date '+%H:%M:%S') start: A at $POS"
  ~/sentinel-venv/Scripts/python paper/tools/run_e5_grid.py --g "$G" --a "$A" --m "$M" --out "$OUT" --defences cookie --attacks FORGE \
    --echo-same --flood 300 --reps 1 --tag "rssi$POS" 2>&1 | grep -a "=== run\|Traceback\|rror"
  echo "=== $(date '+%H:%M:%S') end"; } | tee -a "$OUT/session.log"
