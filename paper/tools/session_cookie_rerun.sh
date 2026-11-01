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
case "${1:-}" in insider*) OUT=paper/data/E_insider_echo ;; esac
GRID="$PY paper/tools/run_e5_grid.py $P --defences cookie gate --out $OUT"
case "${1:-}" in
  smoke)  $GRID --attacks OFF --reps 1 --baseline 20 --settle 10 --flood 180 --recovery 5 --tag smoke ;;
  grid)   $GRID --attacks OFF --reps 3 --tag noattack
          $GRID --attacks FORGE --echo --reps 5 --tag oldecho
          $GRID --attacks FORGE --echo-same --reps 5 --tag sameseq ;;
  budget) $PY paper/tools/run_e5_grid.py $P --defences gate --attacks FORGE --echo-same --flood 900 --pause 260 \
              --reps 3 --out $OUT --tag budget15 ;;
  # controls (about 3 h): same firmware and rig as grid. No defence for reference; FORGE without echo, to separate the
  # echo's effect on the gateway; 15 min with no attack, for power drift; 15 min under cookie, which has no budget.
  controls) $PY paper/tools/run_e5_grid.py $P --defences none --attacks OFF --reps 3 --out $OUT --tag refnone
          $PY paper/tools/run_e5_grid.py $P --defences none --attacks FORGE --reps 5 --out $OUT --tag refnone
          $GRID --attacks FORGE --reps 3 --tag noecho
          $PY paper/tools/run_e5_grid.py $P --defences gate --attacks OFF --flood 900 --reps 3 --out $OUT --tag control15
          $PY paper/tools/run_e5_grid.py $P --defences cookie --attacks FORGE --echo-same --flood 900 \
              --reps 3 --out $OUT --tag long15 ;;
  # Needs A flashed with the cached-HELLO insider; F and G stay at 7afdea4. Check cookie_echoes > 0 in the smoke's A log.
  insider-smoke) $GRID --attacks INSIDER --echo-same --reps 1 --baseline 20 --settle 10 --flood 120 --recovery 5 \
              --tag insiderecho_smoke ;;
  # insider (about 4.7 h): an insider that echoes, which every earlier run failed to test.
  # At about 2.6 admits/s (crypto slot full) it charges 53 mW against a 50 mW refill, so 600 s shows the drain, not an empty
  # bucket. Then plain INSIDER on this firmware, and cookie against gate on the FORGE echo, interleaved this time.
  insider) $PY paper/tools/run_e5_grid.py $P --defences none cookie gate --attacks INSIDER --echo-same --flood 600 \
              --reps 3 --out $OUT --tag insiderecho
          $GRID --attacks INSIDER --reps 3 --tag insiderplain
          $GRID --attacks FORGE --echo-same --flood 900 --pause 260 --reps 3 --tag paired15 ;;
  *) echo "usage: $0 smoke|grid|budget|controls|insider-smoke|insider"; exit 2 ;;
esac
