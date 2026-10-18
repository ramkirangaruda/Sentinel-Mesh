#!/usr/bin/env python3
"""Summarise E5 runs from the raw logs in paper/data/E_phase6/runs/ (never edits them).

  python paper/analysis/e5_summary.py [runs_dir] [--csv out.csv]

Per run it reads the timeline (when the defence was set, when the attack started
and stopped) and G's log, and reports counter deltas over the attack window:
  * gate decisions from G's `LOG field1 ... spend= challenge= drop= busy_drop=
    hs_ok= hs_fail=` relay of field-1's counters (so it still works when F's own
    serial is not wired during energy runs),
  * the legitimate gateway's handshakes from `LOG gw stats hs started= ok=`
    (per-attempt success, not just "it connected").
Per cell (defence, attack, rate, echo) it prints n and the mean and 95% CI
(Student t) of the legit success rate; n < 5 is flagged. Victim joules per
attacker joule needs the INA219 rig and is NOT computed here.
"""
import csv, glob, math, os, re, statistics, sys
from collections import defaultdict

T95 = {1: 12.71, 2: 4.30, 3: 3.18, 4: 2.78, 5: 2.57, 6: 2.45, 7: 2.36, 8: 2.31, 9: 2.26, 10: 2.23}
F1_KEYS = ["spend", "challenge", "drop", "busy_drop", "hs_ok", "hs_fail"]
GW_KEYS = ["started", "ok", "failed"]


def ci95(xs):
    if len(xs) < 2:
        return float("nan")
    return T95.get(len(xs) - 1, 1.96) * statistics.stdev(xs) / math.sqrt(len(xs))


def timeline(path):
    ev = []
    for ln in open(path, encoding="utf-8", errors="replace"):
        m = re.match(r"\[\s*([\d.]+)s\].*-> (\w): (.*)", ln)
        if m:
            ev.append((float(m[1]), m[2], m[3].strip()))
    return ev


def series(path, prefix, keys):
    out = []
    for ln in open(path, encoding="utf-8", errors="replace"):
        m = re.match(r"\[\s*([\d.]+)s\] " + prefix, ln)
        if m:
            out.append((float(m[1]), {k: int(v) for k, v in re.findall(r"(\w+)=(\d+)", ln) if k in keys}))
    return out


def value_at(s, t):
    last = None
    for ts, d in s:
        if ts > t:
            break
        last = d
    return last


def delta(s, t0, t1, keys):
    a, b = value_at(s, t0), value_at(s, t1)
    if not a or not b:
        return None
    return {k: b.get(k, 0) - a.get(k, 0) for k in keys}


def summarise(tl_path):
    base = tl_path[: -len("_timeline.txt")]
    g = base + "_G.log"
    if not os.path.exists(g):
        return None
    ev = timeline(tl_path)
    on = next(((t, l.split()[1]) for t, k, l in ev if k == "A" and l.startswith("MODE") and l != "MODE OFF"), None)
    if not on:
        return None
    t_on = on[0]
    t_off = next((t for t, k, l in ev if k == "A" and l == "MODE OFF" and t > t_on), None)
    if t_off is None:
        return None
    defence = next((l.split()[1] for t, k, l in ev if k == "G" and l.startswith("DEFENSE") and l != "DEFENSE none"), "none")
    rate = next((l.split()[1] for t, k, l in ev if k == "A" and l.startswith("RATE")), "")
    echo = any(l == "ECHO on" for t, k, l in ev)
    row = dict(run=os.path.basename(base), defence=defence, attack=on[1], rate=rate, echo=echo)
    d = delta(series(g, "LOG field1 ", F1_KEYS), t_on, t_off, F1_KEYS)
    if d:
        row.update({"atk_" + k: v for k, v in d.items()})
    w = delta(series(g, "LOG gw stats hs ", GW_KEYS), t_on, t_off, GW_KEYS)
    if w:
        row["legit_started"], row["legit_ok"] = w["started"], w["ok"]
        row["legit_rate"] = w["ok"] / w["started"] if w["started"] else float("nan")
    return row


def main():
    args = [x for x in sys.argv[1:] if not x.startswith("--") and x != (sys.argv[sys.argv.index("--csv") + 1] if "--csv" in sys.argv else None)]
    runs = args[0] if args else os.path.join("paper", "data", "E_phase6", "runs")
    csv_out = sys.argv[sys.argv.index("--csv") + 1] if "--csv" in sys.argv else None
    rows = [r for r in (summarise(p) for p in sorted(glob.glob(os.path.join(runs, "*_timeline.txt")))) if r]
    if not rows:
        print("no complete runs found in", runs)
        return
    cols = ["run", "defence", "attack", "rate", "echo", "atk_spend", "atk_challenge", "atk_drop",
            "atk_busy_drop", "atk_hs_ok", "atk_hs_fail", "legit_started", "legit_ok", "legit_rate"]
    print("\t".join(cols))
    for r in rows:
        print("\t".join(f"{r[c]:.2f}" if isinstance(r.get(c), float) else str(r.get(c, "")) for c in cols))
    cells = defaultdict(list)
    for r in rows:
        x = r.get("legit_rate")
        if x is not None and x == x:
            cells[(r["defence"], r["attack"], r["rate"], r["echo"])].append(x)
    print("\nlegit handshake success during the attack (mean +- 95% CI over runs)")
    for k, xs in sorted(cells.items(), key=str):
        flag = "" if len(xs) >= 5 else "   <- n<5: not enough for a claim"
        print(f"  defence={k[0]:<9} attack={k[1]:<10} rate={k[2] or '-':<3} echo={k[3]!s:<5} "
              f"n={len(xs)}  {statistics.mean(xs):.2f} +- {ci95(xs):.2f}{flag}")
    if csv_out:
        with open(csv_out, "w", newline="") as f:
            w = csv.DictWriter(f, cols, extrasaction="ignore")
            w.writeheader()
            w.writerows(rows)


if __name__ == "__main__":
    main()
