#!/usr/bin/env python3
"""Summarise the bound-cookie rerun from the raw logs in paper/data/E_cookie_fix/ (never edits them).

  python paper/analysis/cookie_fix_summary.py [runs_dir] [--csv out.csv]

Per run, over the attack window (or the same window with no attack):
  * extra power of F against the run's own baseline, from M's NRG power_mw (never amps), calibrated with energy.py;
  * field-1's decisions from G's relay of its counters, which only arrive while F has a session, so a window edge can
    be a few seconds stale;
  * the real gateway's handshakes from `LOG gw stats` (per attempt), and A's echoes (cumulative, so differenced).
For long runs it also splits the attack at the first drop, when the budget has emptied. Drops are the budget's only
source here because F has no data cable, so `budget_j` is seen only in occasional gate_decision reports.
"""
import csv, glob, math, os, re, statistics, sys
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from energy import correct_power_mw

T95 = {1: 12.71, 2: 4.30, 3: 3.18, 4: 2.78, 5: 2.57, 6: 2.45, 7: 2.36, 8: 2.31, 9: 2.26}
TS = re.compile(r"^\[\s*([\d.]+)s\]\s?(.*)")
F1 = re.compile(r"LOG field1 .*?spend=(\d+) challenge=(\d+) drop=(\d+) busy_drop=(\d+) hs_ok=(\d+) hs_fail=(\d+)")
GW = re.compile(r"LOG gw stats hs started=(\d+) ok=(\d+) failed=(\d+)")
NRG = re.compile(r'NRG \{.*?"power_mw":(-?[\d.]+),"volts":(-?[\d.]+)')
RSSI = re.compile(r'"node":"gateway".*?"rssi_mean":(-?[\d.]+)')
ECHO = re.compile(r"LOG attacker stats .*?frames=(\d+) .*?cookie_echoes=(\d+)")
F1_KEYS = ["spend", "challenge", "drop", "busy", "f_ok", "f_fail"]


def lines(path):
    for ln in open(path, encoding="utf-8", errors="replace"):
        m = TS.match(ln.rstrip("\n"))
        if m:
            yield float(m[1]), m[2]


def ci95(xs):
    return T95.get(len(xs) - 1, 1.96) * statistics.stdev(xs) / math.sqrt(len(xs)) if len(xs) > 1 else float("nan")


def at(series, t):
    """Last counter reading at or before t."""
    out = None
    for ts, v in series:
        if ts > t:
            break
        out = v
    return out


def delta(series, t0, t1):
    a, b = at(series, t0), at(series, t1)
    if a is None or b is None:
        return None
    return [y - x for x, y in zip(a, b)]


def wilson(k, n, z=1.96):
    """95 % interval for a proportion; handshakes are treated as independent, which is approximate."""
    if not n:
        return float("nan"), float("nan")
    p, d = k / n, 1 + z * z / n
    mid, half = (p + z * z / (2 * n)) / d, z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return max(0.0, mid - half), min(1.0, mid + half)


def mean_p(nrg, t0, t1):
    xs = [p for t, p in nrg if t0 <= t < t1]
    return (statistics.mean(xs), len(xs)) if xs else (float("nan"), 0)


def run_summary(tl_path):
    base = tl_path[: -len("_timeline.txt")]
    ev = [(float(m[1]), m[2], m[3].strip()) for m in
          (re.match(r"\[\s*([\d.]+)s\].*-> (\w): (.*)", l) for l in open(tl_path)) if m]
    defs = [(t, l.split()[1]) for t, k, l in ev if k == "G" and l.startswith("DEFENSE")]
    t_def, defence = defs[1]
    modes = [(t, l.split()[1]) for t, k, l in ev if k == "A" and l.startswith("MODE")]
    t_on, attack = modes[1]
    t_off = modes[2][0]
    echo = next((l.split()[1] for t, k, l in ev if k == "A" and l.startswith("ECHO")), "off")
    f1, gw, nrg, rssi = [], [], [], []
    for t, s in lines(base + "_G.log"):
        m = F1.search(s)
        if m:
            f1.append((t, [int(x) for x in m.groups()]))
        m = GW.search(s)
        if m:
            gw.append((t, [int(x) for x in m.groups()]))
        m = RSSI.search(s)
        if m and float(m[1]) != 0:
            rssi.append((t, float(m[1])))
    for t, s in lines(base + "_M.log"):
        m = NRG.search(s)
        if m:
            nrg.append((t, correct_power_mw(float(m[1]), float(m[2]))))
    echoes = frames = None
    for t, s in lines(base + "_A.log"):
        m = ECHO.search(s)
        if m:
            frames, echoes = int(m[1]), int(m[2])
    idle, n_idle = mean_p(nrg, 5, t_def)
    during, n_during = mean_p(nrg, t_on + 5, t_off)
    rec, _ = mean_p(nrg, t_off + 5, defs[2][0] if len(defs) > 2 else t_off + 60)
    length = t_off - t_on
    d = delta(f1, t_on, t_off + 3) or [None] * 6
    g = delta(gw, t_on, t_off + 10) or [None] * 3
    r = {"run": os.path.basename(base), "defence": defence, "attack": attack, "echo": echo, "attack_s": round(length),
         "idle_mw": idle, "attack_mw": during, "recovery_mw": rec, "extra_mw": during - idle,
         "drift_mw": rec - idle, "started": g[0], "ok": g[1], "failed": g[2],
         "rssi": statistics.mean(v for t, v in rssi if t_on <= t < t_off) if any(t_on <= t < t_off for t, v in rssi)
         else float("nan"), "echo_cum": echoes, "frames_cum": frames, "nrg_rows": len(nrg),
         "recovery_ok": (delta(gw, t_off + 10, defs[2][0]) or [None, None])[1]}
    if length > 300:
        r["bins"] = [mean_p(nrg, t_on + b, t_on + b + 150)[0] - idle for b in range(5, 755, 150)]
    r.update(dict(zip(F1_KEYS, d)))
    # first relayed drop: the budget has emptied by then (cookie has no budget, and gate has none before this)
    empty = next((t for t, v in f1 if t >= t_on and at(f1, t_on) and v[2] > at(f1, t_on)[2]), None)
    r["t_empty_s"] = round(empty - t_on) if empty else None
    if empty and length > 300:
        after, _ = mean_p(nrg, empty + 5, t_off)
        before, _ = mean_p(nrg, t_on + 5, empty)
        da, db = delta(f1, empty, t_off + 3), delta(f1, t_on, empty)
        r.update(before_mw=before - idle, after_mw=after - idle,
                 spend_s_before=db[0] / (empty - t_on), spend_s_after=da[0] / (t_off + 3 - empty),
                 drop_s_after=da[2] / (t_off + 3 - empty))
        g_b, g_a = delta(gw, t_on, empty), delta(gw, empty, t_off + 10)
        r.update(ok_before=g_b[1], started_before=g_b[0], ok_after=g_a[1], started_after=g_a[0])
    return r


def main():
    args = sys.argv[1:]
    out = None
    if "--csv" in args:
        i = args.index("--csv")
        out = args[i + 1]
        del args[i:i + 2]
    runs_dir = args[0] if args else os.path.join("paper", "data", "E_cookie_fix")
    runs = [run_summary(p) for p in sorted(glob.glob(os.path.join(runs_dir, "*_timeline.txt")))
            if os.path.exists(p[: -len("_timeline.txt")] + "_M.log")
            and sum(1 for l in open(p) if "-> G: DEFENSE" in l) == 3]
    prev = prev_f = None
    for r in runs:      # A's echo counter is cumulative, so a run counts only if the run before it has a reading too
        r["echoes"] = r["echo_cum"] - prev if r["echo_cum"] is not None and prev is not None else None
        r["frames_s"] = (r["frames_cum"] - prev_f) / r["attack_s"] if r["frames_cum"] is not None and prev_f is not None else None
        prev, prev_f = r["echo_cum"], r["frames_cum"]
    print(f"{'run':<52}{'idle':>7}{'extra':>7}{'drift':>7}{'rssi':>6}{'spend':>6}{'chal':>6}{'drop':>6}{'busy':>6}"
          f"{'echo':>6}  gw ok/started")
    for r in runs:
        print(f"{r['run'][:51]:<52}{r['idle_mw']:7.1f}{r['extra_mw']:7.1f}{r['drift_mw']:7.1f}{r['rssi']:6.0f}"
              f"{str(r['spend']):>6}{str(r['challenge']):>6}{str(r['drop']):>6}{str(r['busy']):>6}"
              f"{str(r['echoes']):>6}  {r['ok']}/{r['started']}")
    cells = defaultdict(list)
    for r in runs:
        if "smoke" not in r["run"]:
            tag = re.search(r"_(noattack|oldecho|sameseq|budget15|refnone|noecho|control15|long15)_", r["run"])
            cells[(r["defence"], r["attack"], tag[1] if tag else "?")].append(r)
    print(f"\n{'defence':<8}{'attack':<7}{'tag':<11}{'n':>2}{'extra mW':>16}{'drift mW':>10}{'spend/s':>9}{'chal/s':>8}"
          f"{'drop/s':>8}{'echo/run':>9}{'gw ok/started':>15}{'rate':>7}")
    for k, v in sorted(cells.items()):
        ex = [x["extra_mw"] for x in v]
        sec = v[0]["attack_s"]
        avg = lambda key: statistics.mean(x[key] or 0 for x in v)
        ok, st = sum(x["ok"] or 0 for x in v), sum(x["started"] or 0 for x in v)
        ec = [x["echoes"] for x in v if x["echoes"] is not None]
        print(f"{k[0]:<8}{k[1]:<7}{k[2]:<11}{len(v):>2}{statistics.mean(ex):8.1f} +-{ci95(ex):5.1f}"
              f"{statistics.mean(x['drift_mw'] for x in v):10.1f}{avg('spend') / sec:9.2f}{avg('challenge') / sec:8.2f}"
              f"{avg('drop') / sec:8.2f}{(statistics.mean(ec) if ec else float('nan')):9.0f}{f'{ok}/{st}':>15}"
              f"{100 * ok / st if st else float('nan'):6.0f}%")
    print(f"\n{'real gateway by attacker load':<34}{'frames/s':>9}{'ok/started':>12}{'rate':>6}  95 % interval")
    for name, tags in [("no attack", ("noattack", "control15", "refnone")), ("FORGE, no echo", ("noecho",)),
                       ("FORGE, no echo, no defence", ("refnone",)), ("same-seq echo, 120 s", ("sameseq",)),
                       ("same-seq echo, 900 s, gate", ("budget15",)), ("same-seq echo, 900 s, cookie", ("long15",)),
                       ("old echo", ("oldecho",))]:
        v = [x for k, c in cells.items() if k[2] in tags and (k[1] == "OFF") == (name == "no attack") for x in c]
        fr = [x["frames_s"] for x in v if x["frames_s"] is not None]
        ok, st = sum(x["ok"] or 0 for x in v), sum(x["started"] or 0 for x in v)
        lo, hi = wilson(ok, st)
        print(f"{name:<34}{(statistics.mean(fr) if fr else float('nan')):9.0f}{f'{ok}/{st}':>12}{100 * ok / st:5.0f}%"
              f"  {100 * lo:.0f}-{100 * hi:.0f} %")
    print("\nExtra power per 150 s of a long attack (mW):")
    for r in runs:
        if "bins" in r and r["attack"] != "OFF":
            print(f"{r['run'][:51]:<52}" + " ".join(f"{b:6.1f}" for b in r["bins"]) + f"   gw ok in recovery {r['recovery_ok']}")
    longs = [r for r in runs if "t_empty_s" in r and r.get("after_mw") is not None]
    if longs:
        print("\nLong runs, split at the first relayed drop:")
        for r in longs:
            print(f"{r['run'][:51]:<52} empty +{r['t_empty_s']}s  extra before {r['before_mw']:.1f} after {r['after_mw']:.1f} mW"
                  f"  spend/s {r['spend_s_before']:.2f} -> {r['spend_s_after']:.2f}  drop/s {r['drop_s_after']:.2f}"
                  f"  gw {r['ok_before']}/{r['started_before']} -> {r['ok_after']}/{r['started_after']}")
    if out:
        keys = sorted({k for r in runs for k in r} - {"bins"})
        with open(out, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=keys, extrasaction="ignore")
            w.writeheader()
            w.writerows(runs)


if __name__ == "__main__":
    sys.exit(main())
