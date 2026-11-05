"""Figure 2: field-1's corrected power over time under FLOOD, one run per defence
(paper/data/E5_rig/, 2026-10-25, rep1 of each; power_mw only -- never the aliased amps sample,
see energy.py's docstring). Uses the same session-2 INA219 correction as every other figure/table
in this paper (paper/analysis/energy.py), so this is not a separate, uncorrected read of the logs.

  python paper/analysis/fig_defence_power.py

Each defence's attack window start/end comes from its own timeline.txt (the "-> A: MODE FLOOD"
and the next "-> A: MODE OFF" lines), not a fixed offset, since the settle period differs
slightly run to run. Time is zeroed at that run's own attack start.
"""
import os
import re
import sys

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import energy  # noqa: E402

DATA = os.path.join(HERE, "..", "data", "E5_rig")

# (defence label, file prefix) -- rep1 of each, same night, FLOOD attack (paper/data/E5_rig/).
RUNS = [
    ("none", "20261025_020140_none_flood_e5_rep1"),
    ("ratelimit", "20261025_021621_ratelimit_flood_e5_rep1"),
    ("cookie", "20261025_023102_cookie_flood_e5_rep1"),
    ("gate v2", "20261025_024543_gate_flood_e5_rep1"),
]


def attack_window(timeline_path):
    start = end = None
    for line in open(timeline_path, encoding="utf-8", errors="replace"):
        m = re.match(r"\[\s*([\d.]+)s\].*-> A: (.*)", line)
        if not m:
            continue
        t, cmd = float(m[1]), m[2].strip()
        if cmd == "MODE FLOOD" and start is None:
            start = t
        elif cmd == "MODE OFF" and start is not None and end is None and t > start:
            end = t
    return start, end


def main():
    fig, ax = plt.subplots(figsize=(3.5, 2.2))
    window_len = None
    for label, prefix in RUNS:
        m_path = os.path.join(DATA, f"{prefix}_M.log")
        tl_path = os.path.join(DATA, f"{prefix}_timeline.txt")
        start, end = attack_window(tl_path)
        if start is None:
            print(f"no FLOOD window found in {tl_path}, skipping {label}")
            continue
        log = energy.parse(m_path)
        xs = [s.t - start for s in log.seconds]
        ys = [s.power_mw for s in log.seconds]
        ax.plot(xs, ys, lw=0.8, label=label)
        if window_len is None and end is not None:
            window_len = end - start
    if window_len:
        ax.axvspan(0, window_len, color="0.9", zorder=0)
    ax.set_xlabel("time from FLOOD start (s)")
    ax.set_ylabel("field-1 power (mW)")
    ax.legend(fontsize=7, frameon=False, ncol=2)
    ax.tick_params(labelsize=7)
    ax.xaxis.label.set_size(8)
    ax.yaxis.label.set_size(8)
    fig.tight_layout()
    out = os.path.join(HERE, "..", "ieee", "fig_defence_flood.pdf")
    fig.savefig(out)
    print(f"wrote {out}")


if __name__ == "__main__":
    main()
