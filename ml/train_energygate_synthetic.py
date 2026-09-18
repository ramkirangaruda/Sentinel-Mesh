"""Train EnergyGate on SIMULATED traces and export a header the firmware can
compile in -- for use until real board recordings exist.

The data is ml/tests/generate_synthetic_traces.py's hand-written generator, so
the model learns our own assumptions about what an attack looks like. Its
accuracy is NOT a result and is never written to reports/metrics.json; the
exported header carries a SIMULATED banner saying so. Replace it with
`make energygate` output as soon as real traces are in data/traces/.

    python train_energygate_synthetic.py            # writes export/energygate_synthetic.h
    python train_energygate_synthetic.py --firmware # ...and copies it into firmware/

The header is parity-checked (compiled with gcc, run against sklearn on 500
rows) before it is written anywhere the firmware can see it.
"""
import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile

import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "tests"))

from sentinel_ml import energygate  # noqa: E402
import generate_synthetic_traces as gen  # noqa: E402
from test_energygate_pipeline import (FEATURE_RANGES, HARNESS_SRC,  # noqa: E402
                                      PROB_TOLERANCE, SYNTH_REAL_LABELS)

EXPORT_PATH = os.path.join(HERE, "export", "energygate_synthetic.h")
METRICS_PATH = os.path.join(HERE, "reports", "energygate_synthetic_metrics.json")
FIRMWARE_HEADER = os.path.join(HERE, "..", "firmware", "lib", "sentinel_proto", "include",
                               "sentinel_proto", "energygate_model.h")

BANNER = [
    "SIMULATED -- NOT A RESULT.",
    "Trained on synthetic Trace rows from ml/tests/generate_synthetic_traces.py,",
    "not on real board recordings. It encodes our own assumptions about attack",
    "traffic. Replace with the output of `make energygate` (ml/README.md, phase 3)",
    "once real traces exist in ml/data/traces/. Never present its accuracy as a",
    "measured result.",
]


def parity_check(clf, header_path, n=500, seed=99):
    """Compile the header with gcc and compare to sklearn on n boundary-stressing rows."""
    rng = np.random.default_rng(seed)
    X = np.column_stack([rng.uniform(*FEATURE_RANGES[f], size=n) for f in energygate.FEATURE_ORDER])
    with tempfile.TemporaryDirectory() as tmp:
        # The harness includes "synthetic_energygate.h". A quoted include searches the
        # source file's own folder first, so compile a COPY of the harness in tmp --
        # otherwise a stale tests/synthetic_energygate.h from an earlier test run wins
        # and this would silently check the wrong model.
        shutil.copy(header_path, os.path.join(tmp, "synthetic_energygate.h"))
        harness = os.path.join(tmp, "energygate_harness.c")
        shutil.copy(HARNESS_SRC, harness)
        exe = os.path.join(tmp, "harness.exe")
        csv_path = os.path.join(tmp, "rows.csv")
        np.savetxt(csv_path, X, delimiter=",", fmt="%.9g")
        subprocess.run(["gcc", "-O2", harness, "-o", exe], check=True)
        out = subprocess.run([exe, csv_path], check=True, capture_output=True, text=True).stdout
    c_prob = np.array([float(v) for v in out.split()])
    py_prob = clf.predict_proba(X)[:, 1]
    assert len(c_prob) == len(py_prob), f"C emitted {len(c_prob)} rows, Python {len(py_prob)}"
    worst = float(np.abs(c_prob - py_prob).max())
    assert worst <= PROB_TOLERANCE, f"C and Python disagree by up to {worst:.2e}"
    return worst


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sessions", type=int, default=30,
                    help="synthetic recording sessions; more sessions stop the tree latching onto "
                         "per-session constants like battery_pct")
    ap.add_argument("--depth", type=int, default=4)
    ap.add_argument("--firmware", action="store_true", help="also copy the header into firmware/")
    a = ap.parse_args()

    gen.main(n_sessions=a.sessions, rows_per_session=120, seed=0)
    clf, metrics = energygate.train(gen.OUT_DIR, max_depth=a.depth, real_labels=SYNTH_REAL_LABELS)

    importances = dict(zip(energygate.FEATURE_ORDER, (round(float(v), 3) for v in clf.feature_importances_)))
    metrics.update(
        SIMULATED=True,
        note="synthetic data from ml/tests/generate_synthetic_traces.py; not a result",
        max_depth=a.depth, leaves=int(clf.get_n_leaves()), nodes=int(clf.tree_.node_count),
        feature_importances=importances,
    )

    energygate.export_c(clf, EXPORT_PATH, banner=BANNER)
    worst = parity_check(clf, EXPORT_PATH)
    metrics["c_vs_python_max_abs_diff_500_rows"] = worst
    os.makedirs(os.path.dirname(METRICS_PATH), exist_ok=True)
    with open(METRICS_PATH, "w") as f:
        json.dump(metrics, f, indent=2, default=str)

    print(json.dumps({k: metrics[k] for k in ("rows", "real_pct", "leaves", "nodes",
                                                "feature_importances", "leave_one_session_out")}
                     if a.sessions <= 10 else
                     {k: metrics[k] for k in ("rows", "real_pct", "leaves", "nodes", "feature_importances")},
                     indent=2, default=str))
    accs = [v["acc"] for v in metrics["leave_one_session_out"].values()]
    print(f"SIMULATED leave-one-session-out accuracy: mean {np.mean(accs):.3f}, min {min(accs):.3f} "
          f"over {len(accs)} sessions (NOT a real result)")
    print(f"parity: C == Python on 500 rows (max diff {worst:.2e})")
    print(f"header: {EXPORT_PATH}  ({os.path.getsize(EXPORT_PATH)} bytes of source)")

    if a.firmware:
        shutil.copy(EXPORT_PATH, FIRMWARE_HEADER)
        print(f"copied to {os.path.normpath(FIRMWARE_HEADER)}")


if __name__ == "__main__":
    main()
