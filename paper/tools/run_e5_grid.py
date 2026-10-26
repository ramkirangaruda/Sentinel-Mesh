#!/usr/bin/env python3
"""E5 grid: defence x attack x repeats, one run_flood_test run per cell.

  python paper/tools/run_e5_grid.py --g COM6 --f COM8 --a COM7 --reps 5 \
         --defences none ratelimit cookie gate --attacks FLOOD INSIDER SLOW_DRIP

Each run is about 5 min (baseline 60 + settle 30 + attack 120 + recovery 60),
so 4 defences x 3 attacks x 5 reps is about 5 hours: use --dry-run to see the
plan and time first, and --reps 1 for a smoke test. Runs are interleaved
(rep-major), so stopping part way still leaves every cell with equal repeats.

Not scripted (needs a reflash, so a human step): gate v1. Flash
`field_node_bench_gatev1`, then run with --defences gate --tag v1.
ECHO-INSIDER: --attacks INSIDER --echo (applies to every cell in that call, so
run it as its own grid). Rate sweep: --attacks FLOOD INSIDER --rates 5 20 50
(INSIDER's real rate is capped by the attacker's own signing time).
Raw logs are never edited; a bad run stays and is marked excluded=y in
paper/runlog.csv by hand.
"""
import itertools, os, sys, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def main():
    import run_flood_test as r
    ap = r.build_parser()
    ap.add_argument("--defences", nargs="+", default=["none", "ratelimit", "cookie", "gate"])
    ap.add_argument("--attacks", nargs="+", default=["FLOOD", "INSIDER", "SLOW_DRIP"])
    ap.add_argument("--rates", nargs="*", type=int, default=[None], help="FLOOD RATE sweep, Hz")
    ap.add_argument("--reps", type=int, default=5)
    ap.add_argument("--pause", type=int, default=20, help="s between runs")
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()
    # run_flood_test requires --g/--f/--a only to open ports; a dry run needs none
    cells = []
    for rep in range(1, a.reps + 1):
        for d, atk, rate in itertools.product(a.defences, a.attacks, a.rates):
            if rate and atk not in ("FLOOD", "INSIDER"):  # the attacker obeys RATE in these modes
                continue
            cells.append((rep, d, atk, rate))
    per = a.baseline + a.settle + a.flood + a.recovery + a.pause + 5
    print(f"{len(cells)} runs, about {len(cells) * per / 60:.0f} min total")
    if a.dry_run:
        for c in cells:
            print("  rep %d  defence=%s  attack=%s  rate=%s" % c)
        return
    if sys.platform == "win32":
        # keep the laptop from idle-sleeping for this process only (ES_CONTINUOUS | ES_SYSTEM_REQUIRED);
        # released automatically when the script exits; no power settings are changed
        import ctypes
        ctypes.windll.kernel32.SetThreadExecutionState(0x80000000 | 0x00000001)
        # above-normal priority for this process only, so a busy CPU (e.g. a GPU job) cannot starve the
        # serial readers; Windows does not pass this on from a parent shell
        ctypes.windll.kernel32.SetPriorityClass(ctypes.windll.kernel32.GetCurrentProcess(), 0x00008000)
    base_tag = a.tag
    for i, (rep, d, atk, rate) in enumerate(cells, 1):
        print(f"\n=== run {i}/{len(cells)}: rep {rep} defence={d} attack={atk} rate={rate}")
        a.defence, a.attack, a.rate = d, atk, rate
        a.tag = f"{base_tag}_rep{rep}" if base_tag else f"rep{rep}"
        r.run(a)
        time.sleep(a.pause)


if __name__ == "__main__":
    sys.exit(main())
