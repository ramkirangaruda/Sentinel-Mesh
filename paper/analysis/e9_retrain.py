"""Section 9: EnergyGate on field-1's recorded traces (paper/data/E9_traces/traces_field1.csv).

Leave-one-session-out (never random: neighbouring rows share a 5 s window). Positive class = attack.
Compares: the carried SIMULATED-trained model (its score p), a hand-tuned rate rule (hs_per_s > 0.5),
and a depth-4 tree retrained on the other sessions, with and without the RSSI features
(rssi_* are 0 when no HELLO arrived, so they leak "any HELLO = attack"). battery_pct is constant: dropped.
Transition rows are excluded. Run with ml/.venv's python (needs scikit-learn).
"""
import os
import sys

import numpy as np
import pandas as pd
from sklearn.metrics import roc_auc_score, roc_curve
from sklearn.tree import DecisionTreeClassifier

HERE = os.path.dirname(os.path.abspath(__file__))
CSV = os.path.join(HERE, "..", "data", "E9_traces", "traces_field1.csv")
FEATS_ALL = ["hs_per_s", "hs_fail", "rssi_mean", "rssi_var", "loss_pct", "dup_pct", "frag_complete_pct"]
FEATS_NO_RSSI = [f for f in FEATS_ALL if not f.startswith("rssi")]


def tpr_at_fpr(y, s, fpr_max=0.01):
    fpr, tpr, _ = roc_curve(y, s)
    ok = fpr <= fpr_max
    return float(tpr[ok].max()) if ok.any() else 0.0


def main():
    df = pd.read_csv(CSV)
    df = df[df.label != "transition"].copy()
    df["y"] = (df.label != "normal").astype(int)
    df["grp"] = df.session.astype(str)
    rows = []
    preds = {"carried (SIMULATED)": [], "rate rule": [], "tree, all 7": [], "tree, no RSSI": []}
    ys, labels = [], []
    for g in sorted(df.grp.unique()):
        tr, te = df[df.grp != g], df[df.grp == g]
        if te.y.nunique() < 2 and tr.y.nunique() < 2:
            continue
        ys.append(te.y.values)
        labels.append(te.label.values)
        preds["carried (SIMULATED)"].append(1 - te.p.values)
        preds["rate rule"].append((te.hs_per_s.values > 0.5).astype(float))
        for name, feats in (("tree, all 7", FEATS_ALL), ("tree, no RSSI", FEATS_NO_RSSI)):
            clf = DecisionTreeClassifier(max_depth=4, random_state=42, class_weight="balanced")
            clf.fit(tr[feats].values, tr.y.values)
            preds[name].append(clf.predict_proba(te[feats].values)[:, 1])
    y = np.concatenate(ys)
    lab = np.concatenate(labels)
    for name, parts in preds.items():
        s = np.concatenate(parts)
        flag = s >= 0.5
        per = {L: float(flag[lab == L].mean()) for L in
               ["SLOW_DRIP", "ADAPTIVE", "ADAPTIVE_SPOOF", "FORGE_ECHO"]}
        rows.append(dict(model=name, auc=roc_auc_score(y, s), tpr_at_1pct_fpr=tpr_at_fpr(y, s),
                         fpr_at_0_5=float(flag[y == 0].mean()), **{f"det_{k}": v for k, v in per.items()}))
    out = pd.DataFrame(rows)
    pd.set_option("display.width", 200)
    print(out.round(3).to_string(index=False))
    out.round(4).to_csv(os.path.join(HERE, "..", "data", "E9_traces", "e9_results.csv"), index=False)


if __name__ == "__main__":
    sys.exit(main())
