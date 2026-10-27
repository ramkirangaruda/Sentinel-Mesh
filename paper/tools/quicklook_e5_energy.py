"""Quick look (person H): extra power of F during the attack window, per defence x attack cell (E5 rig runs).

The paper's version of this analysis is task S3 (paper/analysis/, person S); this is the hardware-side check.
usage: python e5_energy.py <runs dir> <tag substring>
Calibration: I_true = (I_raw + 0.428 mA) / 1.0367 (session 2). Baseline = 5 s after start until DEFENSE is sent.
"""
import glob, json, math, os, re, statistics, sys
from collections import defaultdict

GAIN, OFF = 1.0367, -0.428
T95 = {1: 12.71, 2: 4.30, 3: 3.18, 4: 2.78, 5: 2.57, 6: 2.45, 7: 2.36, 8: 2.31, 9: 2.26}
runs_dir, tag = sys.argv[1], sys.argv[2]


def ci(xs):
    return T95.get(len(xs) - 1, 1.96) * statistics.stdev(xs) / math.sqrt(len(xs)) if len(xs) > 1 else float("nan")


cells = defaultdict(list)
for tl_path in sorted(glob.glob(os.path.join(runs_dir, f"*{tag}*_timeline.txt"))):
    base = tl_path[: -len("_timeline.txt")]
    ev = [(float(m[1]), m[2], m[3].strip()) for m in
          (re.match(r"\[\s*([\d.]+)s\].*-> (\w): (.*)", l) for l in open(tl_path)) if m]
    t_def = [t for t, k, l in ev if k == "G" and l.startswith("DEFENSE")][1]
    defence = [l.split()[1] for t, k, l in ev if k == "G" and l.startswith("DEFENSE")][1]
    t_on, attack = next((t, l.split()[1]) for t, k, l in ev if k == "A" and l.startswith("MODE") and l != "MODE OFF")
    rate = next((l.split()[1] for t, k, l in ev if k == "A" and l.startswith("RATE")), "")
    if rate: attack = f"{attack}@{rate}"
    if any(l == "ECHO on" for t, k, l in ev): attack += "+ECHO"
    t_off = next(t for t, k, l in ev if k == "A" and l == "MODE OFF" and t > t_on)
    nrg = []
    for ln in open(base + "_M.log", encoding="utf-8", errors="replace"):
        m = re.match(r"\[\s*([\d.]+)s\] NRG (\{.*\})", ln)
        if not m:
            continue
        try:
            d = json.loads(m[2])
        except Exception:
            continue
        # power_mw is M's mean over the whole 1 s interval; amps is ONE instantaneous sample (live readout
        # only) and aliases against a periodic attack, so it must not be used. Calibration applied to the mean:
        # P_true = (P_raw - V * OFF) / GAIN with OFF = -0.428 mA.
        nrg.append((float(m[1]), (d["power_mw"] - d["volts"] * OFF) / GAIN))
    b = [p for t, p in nrg if 5 <= t < t_def]
    a = [p for t, p in nrg if t_on + 5 <= t < t_off]
    if not b or not a:
        print("skip", base)
        continue
    extra = statistics.mean(a) - statistics.mean(b)
    cells[(defence, attack)].append((statistics.mean(b), extra, extra * (t_off - t_on) / 1000))

print(f"{'defence':<10}{'attack':<16}{'n':>3}{'idle mW':>9}{'extra mW (mean +- 95% CI)':>30}{'extra % ':>9}{'extra J / window':>18}")
for (d, atk), v in sorted(cells.items()):
    idle = statistics.mean(x[0] for x in v)
    ex = [x[1] for x in v]
    j = [x[2] for x in v]
    print(f"{d:<10}{atk:<16}{len(v):>3}{idle:9.1f}{statistics.mean(ex):18.1f} +- {ci(ex):6.1f}"
          f"{100 * statistics.mean(ex) / idle:8.1f}%{statistics.mean(j):12.2f} +- {ci(j):.2f}")
