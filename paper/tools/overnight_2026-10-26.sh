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
# 5. Ramkiran's MODE FORGE (if pushed by now): build his attacker in a scratch worktree, flash A, check, run.
forge() {
  local PIO=${PIO:-pio} WT=${FORGE_WT:-../forge-wt}
  git fetch -q origin paper/analysis-writing || { echo "=== FORGE: fetch failed, skipped"; return; }
  if ! git show origin/paper/analysis-writing:firmware/src/attacker/main.cpp | grep -q 'MODE FORGE\|"FORGE"'; then
    echo "=== FORGE: not on origin/paper/analysis-writing yet, skipped"; return; fi
  echo "=== FORGE: found at $(git rev-parse --short origin/paper/analysis-writing)"
  git worktree remove --force "$WT" 2>/dev/null; git worktree add -q --detach "$WT" origin/paper/analysis-writing || { echo "=== FORGE: worktree failed"; return; }
  ( cd "$WT/firmware" && "$PIO" run -e attacker -t upload --upload-port "$A" ) > "$OUT/forge_flash.log" 2>&1     || { echo "=== FORGE: build/flash failed (see $OUT/forge_flash.log), skipped"; return; }
  "$PY" - "$A" <<'PYEOF' || { echo "=== FORGE: A did not list FORGE at boot, skipped"; return; }
import serial, sys, time
s = serial.Serial(); s.port, s.baudrate, s.timeout = sys.argv[1], 115200, 0.2; s.dtr = s.rts = False; s.open()
time.sleep(0.1); s.rts = True; time.sleep(0.15); s.rts = False
b = b""; end = time.time() + 6
while time.time() < end: b += s.read(512)
s.close()
sys.exit(0 if b"FORGE" in b else 1)
PYEOF
  grid --defences none cookie gate --attacks FORGE --reps 5 --tag forge
}
forge
echo "=== $(date '+%H:%M:%S') overnight chain done"
