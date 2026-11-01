#!/usr/bin/env bash
# Overnight chain for 2026-11-01: started once, needs no internet or reply. Same runs as `session_cookie_rerun.sh insider`.
# Waits for the running insider-smoke to finish, reads its echo count, then runs each block. A failed block does not stop
# the next. If the smoke's echoes never fired, the echoing insider block is skipped, since it would repeat the excluded runs.
# usage: bash paper/tools/overnight_2026-11-01.sh COMg COMa COMm [smoke_pid]
set -u
G=$1; A=$2; M=$3; SMOKE_PID=${4:-}
PY=~/sentinel-venv/Scripts/python
OUT=paper/data/E_insider_echo
export PYTHONIOENCODING=utf-8
grid() { echo "=== $(date '+%H:%M:%S') start: $*"; "$PY" paper/tools/run_e5_grid.py --g "$G" --a "$A" --m "$M" --out "$OUT" "$@" \
           2>&1 | grep -a "=== run\|Traceback\|rror"; echo "=== $(date '+%H:%M:%S') end (exit ${PIPESTATUS[0]})"; }
if [ -n "$SMOKE_PID" ]; then
  echo "=== $(date '+%H:%M:%S') waiting for smoke, pid $SMOKE_PID"
  while kill -0 "$SMOKE_PID" 2>/dev/null; do sleep 5; done
  sleep 25   # the runner's pause, so F's bucket and the ports settle
fi
ECHOES=$(cat "$OUT"/*insiderecho_smoke*_A.log 2>/dev/null | grep -ao 'cookie_echoes=[0-9]*' | cut -d= -f2 | sort -n | tail -1)
echo "=== $(date '+%H:%M:%S') smoke cookie_echoes max: ${ECHOES:-none}"
# 1. insider that echoes (9 runs, about 116 min). At about 2.6 admits/s it charges 53 mW against a 50 mW refill, so 600 s
#    shows the drain, not an empty bucket.
if [ "${ECHOES:-0}" -gt 0 ]; then
  grid --defences none cookie gate --attacks INSIDER --echo-same --flood 600 --reps 3 --tag insiderecho
else
  echo "=== SKIPPED insiderecho: echoes did not fire in the smoke"
fi
# 2. plain insider on this firmware (6 runs, about 30 min)
grid --defences cookie gate --attacks INSIDER --reps 3 --tag insiderplain
# 3. cookie against gate on the FORGE echo, interleaved (6 runs, about 132 min)
grid --defences cookie gate --attacks FORGE --echo-same --flood 900 --pause 260 --reps 3 --tag paired15
echo "=== $(date '+%H:%M:%S') ALL DONE"
