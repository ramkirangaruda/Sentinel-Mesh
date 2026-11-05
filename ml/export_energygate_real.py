"""Deploy the retrained EnergyGate tree: fit it on every recorded session and export it to the firmware header.

  python ml/export_energygate_real.py [--check]

Source: paper/data/E9_traces/traces_field1.csv (field-1's own features, 6 sessions, one rig). Same tree as the paper's
"tree, no RSSI" row (paper/analysis/e9_retrain.py): depth 4, class_weight balanced, random_state 42, transition rows
excluded. rssi_mean/rssi_var (0 when no HELLO arrived, so they leak) and battery_pct (constant, SIMULATED) are zeroed
before fitting, so the tree never splits on them while the header keeps the firmware's 8-feature FEATURE_ORDER.

The deployed tree is fitted on ALL sessions, so its accuracy on these traces is in-sample and is not reported as a
result. Its expected out-of-sample quality is the leave-one-session-out figure, which this script recomputes, along with
what the firmware's policy thresholds (spend >= 0.7, challenge >= 0.4) would do per attack label, also left out by session.

--check compiles the exported header with gcc, scores every trace row in C, and compares with scikit-learn.
The SIMULATED model it replaces stays in ml/export/energygate_synthetic.h.
"""
import json
import os
import subprocess
import sys
import tempfile

import numpy as np
import pandas as pd
from sklearn.metrics import roc_auc_score
from sklearn.tree import DecisionTreeClassifier

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from sentinel_ml.energygate import FEATURE_ORDER, export_c

HERE = os.path.dirname(os.path.abspath(__file__))
CSV = os.path.join(HERE, "..", "paper", "data", "E9_traces", "traces_field1.csv")
HEADER = os.path.join(HERE, "..", "firmware", "lib", "sentinel_proto", "include", "sentinel_proto", "energygate_model.h")
REPORT = os.path.join(HERE, "reports", "energygate_deployed.json")
UNUSED = ["rssi_mean", "rssi_var", "battery_pct"]
SPEND, CHALLENGE = 0.7, 0.4   # firmware GatePolicyConfig defaults


def features(df):
    x = df[FEATURE_ORDER].astype(float).copy()
    x[UNUSED] = 0.0
    return x.values


def fit(df):
    clf = DecisionTreeClassifier(max_depth=4, random_state=42, class_weight="balanced")
    clf.fit(features(df), (df.label == "normal").astype(int).values)   # class 1 = real, as export_c expects
    return clf


def loso(df):
    """Leave-one-session-out: AUC for attack detection, and policy outcome rates per label."""
    scores = np.empty(len(df))
    for s in sorted(df.session.unique()):
        te = (df.session == s).values
        scores[te] = fit(df[~te]).predict_proba(features(df[te]))[:, 1]
    attack = (df.label != "normal").values
    per_label = {}
    for lab in sorted(df.label.unique()):
        m = (df.label == lab).values
        per_label[lab] = dict(rows=int(m.sum()), spend=round(float((scores[m] >= SPEND).mean()), 3),
                              challenge_band=round(float(((scores[m] >= CHALLENGE) & (scores[m] < SPEND)).mean()), 3),
                              below_challenge=round(float((scores[m] < CHALLENGE).mean()), 3))
    return dict(auc=round(float(roc_auc_score(attack, 1 - scores)), 4), by_label=per_label)


def check(clf, df):
    """Score every row with the exported C and compare with scikit-learn."""
    x = features(df)
    with tempfile.TemporaryDirectory() as d:
        src, exe, inp = os.path.join(d, "t.c"), os.path.join(d, "t.exe"), os.path.join(d, "x.txt")
        np.savetxt(inp, x, fmt="%.9g")
        with open(src, "w") as f:
            f.write('#include <stdio.h>\n#include "energygate_model.h"\n'
                    "int main(int c, char** v) { FILE* in = fopen(v[1], \"r\"); float f[8];\n"
                    "  while (fscanf(in, \"%f %f %f %f %f %f %f %f\", f, f+1, f+2, f+3, f+4, f+5, f+6, f+7) == 8)\n"
                    "    printf(\"%.6f\\n\", energygate_score(f));\n  return 0; }\n")
        subprocess.run(["gcc", "-O2", "-I", os.path.dirname(HEADER), src, "-o", exe], check=True)
        c_scores = np.array(subprocess.run([exe, inp], check=True, capture_output=True, text=True).stdout.split(), float)
    py = clf.predict_proba(x)[:, 1]
    diff = np.abs(c_scores - py)
    return dict(rows=len(py), max_abs_diff=float(diff.max()), same_side_of_0_7=bool(((c_scores >= SPEND) == (py >= SPEND)).all()),
                same_side_of_0_4=bool(((c_scores >= CHALLENGE) == (py >= CHALLENGE)).all()))


def main():
    df = pd.read_csv(CSV)
    df = df[df.label != "transition"].reset_index(drop=True)
    df["session"] = df.session.astype(str)
    clf = fit(df)
    held_out = loso(df)
    export_c(clf, HEADER, banner=[
        "Trained on REAL traces: field-1's own features from paper/data/E9_traces (6 sessions, one rig, one room),",
        "by ml/export_energygate_real.py. Depth 4, no RSSI, battery_pct unused (constant on the rig).",
        f"Leave-one-session-out AUC {held_out['auc']}; fitted on all sessions for deployment, so do not quote its",
        "in-sample accuracy. Traces predate the bound cookie and contain no same-seq echo.",
        "The SIMULATED model it replaced is ml/export/energygate_synthetic.h.",
    ])
    report = dict(source=os.path.relpath(CSV, os.path.join(HERE, "..")).replace(os.sep, "/"), rows=len(df),
                  sessions=sorted(df.session.unique()), features_used=[f for f in FEATURE_ORDER if f not in UNUSED],
                  leave_one_session_out=held_out, thresholds=dict(spend=SPEND, challenge=CHALLENGE))
    if "--check" in sys.argv:
        report["c_vs_sklearn"] = check(clf, df)
    os.makedirs(os.path.dirname(REPORT), exist_ok=True)
    with open(REPORT, "w") as f:
        json.dump(report, f, indent=2)
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
