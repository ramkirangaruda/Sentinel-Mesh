#!/usr/bin/env bash
# Rerun against the (epoch, seq)-bound cookie, on the energy rig. F=field_node_energy powered only through the
# INA219, G=gateway, A=attacker, M=monitor_ina219. F has no data cable, so G's log carries its counters.
#   bash paper/tools/session_cookie_rerun.sh smoke|grid|budget
# smoke (about 8 min): does the real gateway still get in with no attack? Check `LOG hs ok` in the G logs first.
# grid (about 2.2 h): no attack, old echo and same-seq echo, under cookie and gate v2.
# budget (about 1.2 h): same-seq echo for 15 min, long enough to empty the bucket and measure power after it.
#   --pause 260 gives >= 400 s between attacks, so every rep starts from a full bucket.
set -u
PY=~/sentinel-venv/Scripts/python
P="--g ${G:-COM11} --a ${A:-COM4} --m ${M:-COM7}"
OUT=paper/data/E_cookie_fix
GRID="$PY paper/tools/run_e5_grid.py $P --defences cookie gate --out $OUT"
case "${1:-}" in
  smoke)  $GRID --attacks OFF --reps 1 --baseline 20 --settle 10 --flood 180 --recovery 5 --tag smoke ;;
  grid)   $GRID --attacks OFF --reps 3 --tag noattack
          $GRID --attacks FORGE --echo --reps 5 --tag oldecho
          $GRID --attacks FORGE --echo-same --reps 5 --tag sameseq ;;
  budget) $PY paper/tools/run_e5_grid.py $P --defences gate --attacks FORGE --echo-same --flood 900 --pause 260 \
              --reps 3 --out $OUT --tag budget15 ;;
  *) echo "usage: $0 smoke|grid|budget"; exit 2 ;;
esac
