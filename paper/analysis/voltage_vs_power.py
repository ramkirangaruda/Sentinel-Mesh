#!/usr/bin/env python3
"""Does F's supply voltage or A's signal explain the swing in extra power? Reads raw logs only.

  python paper/analysis/voltage_vs_power.py [--csv out.csv]

Extra power here is the same as cookie_fix_summary.py (NRG power_mw, calibrated, attack minus the run's own idle). Extra current
uses the per-second mean in `LOG cal`, calibrated, never the single-sample `amps`. "At 4.85 V" is extra current times 4.85 V: what
the extra power would be with a fixed supply. Runs: every FORGE same-seq echo under cookie, plus the no-defence FORGE references.
"""
import csv, glob, math, os, re, statistics, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from cookie_fix_summary import run_summary, lines
from energy import correct_current_ma, CAL

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "data")
SETS = [("10-31", "E_cookie_fix"), ("11-01/02", "E_insider_echo"), ("11-02 day", "E_repeat"), ("11-02 eve", "E_rssi")]
EXCLUDED = ("20261102_163706", "20261102_165311", "20261102_165804", "20261102_170258")
V_REF = 4.85


def pearson(xs, ys):
    pairs = [(x, y) for x, y in zip(xs, ys) if not (math.isnan(x) or math.isnan(y))]
    return (statistics.correlation(*zip(*pairs)), len(pairs)) if len(pairs) > 2 else (float("nan"), len(pairs))


def electrical(base, t_def, t_on, t_off):
    rows = []
    for t, s in lines(base + "_M.log"):
        m = CAL.search(s)
        if m:
            rows.append((t, float(m[3]), correct_current_ma(float(m[4]))))
    mean = lambda col, a, b: statistics.mean(r[col] for r in rows if a <= r[0] < b)
    return mean(1, 5, t_def), mean(1, t_on + 5, t_off), mean(2, 5, t_def), mean(2, t_on + 5, t_off)


def collect():
    out = []
    for session, folder in SETS:
        for tl in sorted(glob.glob(os.path.join(ROOT, folder, "*_timeline.txt"))):
            name = os.path.basename(tl)
            if name.startswith(EXCLUDED) or "_forge_" not in name:
                continue
            if not (("_cookie_" in name and "echosame" in name) or "_none_" in name):
                continue
            base = tl[: -len("_timeline.txt")]
            r = run_summary(tl)
            ev = [(float(m[1]), m[2]) for m in (re.match(r"\[\s*([\d.]+)s\].*-> \w: (.*)", l) for l in open(tl)) if m]
            t_def = [t for t, l in ev if l.startswith("DEFENSE")][1]
            modes = [t for t, l in ev if l.startswith("MODE")]
            try:
                v0, v1, i0, i1 = electrical(base, t_def, modes[1], modes[2])
            except statistics.StatisticsError:
                continue
            out.append({"session": session, "run": r["run"], "defence": r["defence"], "attack_s": r["attack_s"],
                        "rssi": r["rssi"], "spend_s": (r.get("spend") or 0) / r["attack_s"], "idle_mw": r["idle_mw"],
                        "extra_mw": r["extra_mw"], "v_idle": v0, "v_attack": v1, "dv": v1 - v0, "i_idle": i0, "di_ma": i1 - i0,
                        "fixed_mw": (i1 - i0) * V_REF})
    return out


def corr(rows, label):
    k = lambda f: [r[f] for r in rows]
    print(f"  {label:<26} n={len(rows):>2}  RSSI~extra r={pearson(k('rssi'), k('extra_mw'))[0]:+.2f}  RSSI~fixed-V r="
          f"{pearson(k('rssi'), k('fixed_mw'))[0]:+.2f}  dV~extra r={pearson(k('dv'), k('extra_mw'))[0]:+.2f}  spend/s~fixed-V r="
          f"{pearson(k('spend_s'), k('fixed_mw'))[0]:+.2f}")


def main():
    rows = collect()
    if "--csv" in sys.argv:
        with open(sys.argv[sys.argv.index("--csv") + 1], "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=list(rows[0]))
            w.writeheader()
            w.writerows(rows)
    print("session    defence attack_s rssi  spend/s idle mW  idle mA  bus idle  dV      extra mW  dI mA  at 4.85 V")
    for r in rows:
        if r["session"] == "11-02 eve" or r["attack_s"] > 800:
            print(f"{r['session']:<10} {r['defence']:<7} {r['attack_s']:>6} {r['rssi']:>6.1f} {r['spend_s']:>6.2f} {r['idle_mw']:>8.1f} "
                  f"{r['i_idle']:>7.2f} {r['v_idle']:>8.3f} {r['dv']:>+7.3f} {r['extra_mw']:>+8.1f} {r['di_ma']:>+6.2f} {r['fixed_mw']:>+8.1f}")
    print("\nIdle current against idle bus voltage, all runs here (does F draw a fixed current?):")
    print(f"  bus {min(r['v_idle'] for r in rows):.3f}-{max(r['v_idle'] for r in rows):.3f} V, idle current "
          f"{min(r['i_idle'] for r in rows):.1f}-{max(r['i_idle'] for r in rows):.1f} mA, r = "
          f"{pearson([r['v_idle'] for r in rows], [r['i_idle'] for r in rows])[0]:+.2f}; idle power against bus r = "
          f"{pearson([r['v_idle'] for r in rows], [r['idle_mw'] for r in rows])[0]:+.2f}")
    echo = [r for r in rows if r["defence"] == "cookie"]
    long_echo = [r for r in echo if r["attack_s"] > 800]
    print("\nCorrelations:")
    corr([r for r in echo if r["session"] == "11-02 eve"], "controlled test, 300 s")
    corr(long_echo, "cookie echo, 900 s")
    corr(rows and [r for r in rows if r["defence"] == "none"], "no defence, FORGE")
    print("\nMean ± SD by group, cookie echo:")
    groups = {f"{s}, 900 s": [r for r in long_echo if r["session"] == s] for s, _ in SETS}
    groups["11-02 eve, 300 s"] = [r for r in echo if r["session"] == "11-02 eve"]
    for g, rs in groups.items():
        if len(rs) > 1:
            sd = lambda f: statistics.stdev(r[f] for r in rs)
            m = lambda f: statistics.mean(r[f] for r in rs)
            print(f"  {g:<20} n={len(rs):>2}  extra {m('extra_mw'):+6.1f} ± {sd('extra_mw'):4.1f}   at 4.85 V {m('fixed_mw'):+6.1f} ± {sd('fixed_mw'):4.1f}"
                  f"   RSSI {m('rssi'):6.1f}  spend/s {m('spend_s'):.2f}  dV {m('dv'):+.3f}")


if __name__ == "__main__":
    main()
