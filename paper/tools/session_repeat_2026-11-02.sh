#!/usr/bin/env bash
# Repeat of the two cells whose absolute power moved between sessions: cookie on the FORGE echo (+13.0 on 10-31, +19.7 on 11-02)
# and no defence on FORGE (+19.0 in the paper, +14.7 on 10-31). F, G at 7afdea4, A at 389d74f; nothing is reflashed. About 1.5 h.
# usage: bash paper/tools/session_repeat_2026-11-02.sh COMg COMa COMm
set -u
G=$1; A=$2; M=$3
PY=~/sentinel-venv/Scripts/python
OUT=paper/data/E_repeat
mkdir -p "$OUT"
export PYTHONIOENCODING=utf-8
grid() { echo "=== $(date '+%H:%M:%S') start: $*"; "$PY" paper/tools/run_e5_grid.py --g "$G" --a "$A" --m "$M" --out "$OUT" "$@" \
           2>&1 | grep -a "=== run\|Traceback\|rror"; echo "=== $(date '+%H:%M:%S') end (exit ${PIPESTATUS[0]})"; }
grid --defences none --attacks FORGE --reps 5 --tag refnone
grid --defences cookie --attacks FORGE --echo-same --flood 900 --pause 260 --reps 3 --tag long15
echo "=== $(date '+%H:%M:%S') ALL DONE"
