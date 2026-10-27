#!/usr/bin/env python3
"""Section 9 dataset: field-1's own EnergyGate features, labelled from each run's timeline.

  python paper/analysis/build_traces.py            # writes paper/data/E9_traces/traces_field1.csv

Input: run_flood_test runs whose F log has `FEAT {...}` rows (field_node_bench, 2026-10-27 or later):
paper/data/E9_traces/ (6 attacks x 3 sessions) and paper/data/E_budget/ (FORGE+ECHO, 10-min attack).
One row per FEAT line (1 s apart; the 5 s window slides, so neighbouring rows overlap: split by
`session`, never randomly). Labels come from host time against the timeline:
  attack  : MODE <X> + 5 s  <= t < MODE OFF          (label = X, or FORGE_ECHO when ECHO on)
  normal  : t < MODE <X>    or  t >= MODE OFF + 5 s  (5 s = one full window after the change)
  transition: the 5 s after each change (kept, but leave them out of training and scoring)
`p` is the score from the model the firmware carried (trained on SIMULATED traces), kept for comparison.
"""
import csv, glob, json, os, re

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "data")
FEATURES = ["hs_per_s", "hs_fail", "rssi_mean", "rssi_var", "loss_pct", "dup_pct", "frag_complete_pct", "battery_pct"]
WIN = 5.0


def runs():
    for d in ("E9_traces", "E_budget"):
        for tl in sorted(glob.glob(os.path.join(ROOT, d, "*_timeline.txt"))):
            yield d, tl[: -len("_timeline.txt")]


def main():
    out = os.path.join(ROOT, "E9_traces", "traces_field1.csv")
    n = {}
    with open(out, "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["run", "session", "t_s", "label", *FEATURES, "p", "defence", "budget_j"])
        for d, base in runs():
            ev = [(float(m[1]), m[2], m[3].strip()) for m in
                  (re.match(r"\[\s*([\d.]+)s\].*-> (\w): (.*)", l) for l in open(base + "_timeline.txt")) if m]
            on, mode = next((t, l.split()[1]) for t, k, l in ev if k == "A" and l.startswith("MODE ") and l != "MODE OFF")
            off = next(t for t, k, l in ev if k == "A" and l == "MODE OFF" and t > on)
            if any(k == "A" and l == "ECHO on" for t, k, l in ev):
                mode += "_ECHO"
            name = os.path.basename(base)
            session = ("budget_" if d == "E_budget" else "") + re.search(r"_rep(\d+)$", name)[1]
            for ln in open(base + "_F.log", encoding="utf-8", errors="replace"):
                m = re.match(r"\[\s*([\d.]+)s\] FEAT (\{.*\})", ln)
                if not m:
                    continue
                try:
                    r = json.loads(m[2])
                except ValueError:
                    continue
                t = float(m[1])
                if on + WIN <= t < off:
                    lab = mode
                elif t < on or t >= off + WIN:
                    lab = "normal"
                else:
                    lab = "transition"
                n[lab] = n.get(lab, 0) + 1
                w.writerow([name, session, f"{t:.2f}", lab, *(r[f] for f in FEATURES), r["p"], r["defence"], r["budget_j"]])
    print(out)
    for k, v in sorted(n.items()):
        print(f"  {k:<16}{v:6d}")


if __name__ == "__main__":
    main()
