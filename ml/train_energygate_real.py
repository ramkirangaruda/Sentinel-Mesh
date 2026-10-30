"""Task S7 (paper/WORK_SPLIT.md): retrain EnergyGate on traces recorded from real boards, not
simulated ones, and report how it compares with the SIMULATED-trained model that is currently
shipped (`sentinel_ml/energygate.py` -> `export/energygate.h`) and with a hand-tuned threshold
rule. Separate from `train_energygate.py` (which trains the shipped model from
`data/traces/*.jsonl`, console-style Trace rows) because this reads a different, CSV source:
`paper/data/E9_traces/traces_field1.csv`, field-1's OWN feature vector (FEAT rows the bench
firmware now prints, not the console's Trace events), recorded under gate v2 on real hardware.

  python ml/train_energygate_real.py [--csv paper/data/E9_traces/traces_field1.csv]
                                      [--out ml/reports/energygate_real_metrics.json]

Honesty notes (paper/data/E9_traces/README.md), followed here:
  - Split by session, never randomly: rows are 1 s apart over a 5 s rolling window, so
    neighbouring rows overlap. Evaluation below is leave-one-session-out over the 6 recording
    sessions (3 six-attack sessions + 3 FORGE_ECHO/budget sessions), never a random split.
  - rssi_mean/rssi_var read 0 when no HELLO arrived in the window, which is not a real 0 dBm --
    it is missing data a model could learn as "any signal at all = attack". Reported WITH and
    WITHOUT those two features for exactly this reason.
  - battery_pct is a constant 100 here (no battery on this rig, SIMULATED): dropped.
  - `transition` rows (the few seconds either side of an attack boundary) are excluded: neither
    class describes them cleanly.
  - One rig, one room, one distance: a held-out SESSION is not a held-out ENVIRONMENT. Say so
    wherever these numbers are quoted.
"""
import argparse
import json
import os

import numpy as np
import pandas as pd
from sklearn.metrics import roc_auc_score, roc_curve
from sklearn.tree import DecisionTreeClassifier

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_CSV = os.path.join(HERE, "..", "paper", "data", "E9_traces", "traces_field1.csv")
DEFAULT_OUT = os.path.join(HERE, "reports", "energygate_real_metrics.json")

FEATURES_WITH_RSSI = ["hs_per_s", "hs_fail", "rssi_mean", "rssi_var", "loss_pct", "dup_pct", "frag_complete_pct"]
FEATURES_NO_RSSI = ["hs_per_s", "hs_fail", "loss_pct", "dup_pct", "frag_complete_pct"]
# battery_pct is excluded from both: constant 100 on this rig (SIMULATED), carries nothing.


def load(csv_path):
    df = pd.read_csv(csv_path)
    df = df[df["label"] != "transition"].copy()
    df["attack"] = (df["label"] != "normal").astype(int)   # y = 1 means "this is an attack"
    return df


def leave_one_session_out_scores(df, feature_cols, max_depth=4, seed=42, min_samples_leaf=1):
    """Fits a fresh depth-4 tree (same depth as the shipped model) on every session but one,
    predicts on the held-out session, and pools the held-out predictions from every fold into
    one (y_true, attack_score) pair per row -- never a row scored by a model that saw it."""
    X = df[feature_cols].values.astype(float)
    y = df["attack"].values
    sessions = df["session"].values

    pooled_idx, pooled_y, pooled_score = [], [], []
    per_session = {}
    for s in sorted(set(sessions)):
        te = sessions == s
        tr = ~te
        if len(set(y[tr])) < 2 or te.sum() == 0:
            continue
        clf = DecisionTreeClassifier(max_depth=max_depth, random_state=seed,
                                     min_samples_leaf=min_samples_leaf).fit(X[tr], y[tr])
        real_prob = clf.predict_proba(X[te])[:, list(clf.classes_).index(0)] if 0 in clf.classes_ else np.zeros(te.sum())
        attack_score = 1.0 - real_prob
        pooled_idx.extend(np.flatnonzero(te).tolist())
        pooled_y.extend(y[te].tolist())
        pooled_score.extend(attack_score.tolist())
        if len(set(y[te])) == 2:
            per_session[str(s)] = dict(n=int(te.sum()), auc=round(float(roc_auc_score(y[te], attack_score)), 4))
        else:
            per_session[str(s)] = dict(n=int(te.sum()), auc=None, note="held-out session has only one class")
    order = np.argsort(pooled_idx)   # restore original row order so it lines up with df
    return np.array(pooled_y)[order], np.array(pooled_score)[order], per_session


def hand_tuned_rule_score(df):
    """The exact rule-based stand-in firmware falls back to when no trained model is linked
    (sentinel_proto/energygate.cpp, the #else branch of SENTINEL_ENERGYGATE_TRAINED_MODEL).
    Ported to Python unchanged so this is a real comparison, not an invented baseline. Returns
    an ATTACK score (1 - the rule's "probably legitimate" score)."""
    hs_per_s = df["hs_per_s"].values.astype(float)
    hs_fail = df["hs_fail"].values.astype(float)
    rssi_var = df["rssi_var"].values.astype(float)
    loss_pct = df["loss_pct"].values.astype(float)
    dup_pct = df["dup_pct"].values.astype(float)
    frag_complete_pct = df["frag_complete_pct"].values.astype(float)

    score = np.ones(len(df))
    denom = hs_per_s + hs_fail
    fail_ratio = np.divide(hs_fail, denom, out=np.zeros_like(denom), where=denom > 0)
    score -= 0.4 * fail_ratio
    score -= 0.3 * (1.0 - frag_complete_pct / 100.0)
    score -= 0.15 * (loss_pct / 100.0)
    score -= 0.15 * (dup_pct / 100.0)
    score -= np.where(rssi_var > 20.0, 0.2, 0.0)
    score = np.clip(score, 0.0, 1.0)
    return 1.0 - score   # attack score


def tpr_at_fpr(y_true, attack_score, target_fpr=0.01):
    fpr, tpr, thr = roc_curve(y_true, attack_score)
    # roc_curve's fpr is monotonically non-decreasing; interpolate the TPR at the target FPR.
    return float(np.interp(target_fpr, fpr, tpr))


def summarize(name, y_true, attack_score):
    return dict(
        model=name,
        n=int(len(y_true)),
        auc=round(float(roc_auc_score(y_true, attack_score)), 4),
        tpr_at_1pct_fpr=round(tpr_at_fpr(y_true, attack_score, 0.01), 4),
    )


def per_label_flagged(df, attack_score, threshold):
    out = {}
    for label in sorted(df["label"].unique()):
        mask = (df["label"] == label).values
        if mask.sum() == 0:
            continue
        out[label] = dict(n=int(mask.sum()), mean_attack_score=round(float(attack_score[mask].mean()), 4),
                          flagged_frac=round(float((attack_score[mask] >= threshold).mean()), 4))
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--csv", default=DEFAULT_CSV)
    ap.add_argument("--out", default=DEFAULT_OUT)
    a = ap.parse_args()

    df = load(a.csv)
    y_all = df["attack"].values

    results = {"rows": int(len(df)), "sessions": sorted(df["session"].unique().tolist()),
               "label_counts": df["label"].value_counts().to_dict()}

    # 1. SIMULATED-trained model shipped today: its own score 'p' is already in the CSV
    #    (field-1 printed it live, FEAT rows), one fixed model, no retraining or CV needed.
    sim_attack_score = 1.0 - df["p"].values.astype(float)
    results["simulated_trained_shipped"] = summarize("SIMULATED-trained (shipped)", y_all, sim_attack_score)
    results["simulated_trained_shipped"]["per_label"] = per_label_flagged(df, sim_attack_score, threshold=0.5)

    # 2. Hand-tuned threshold rule (firmware's own non-trained fallback formula).
    rule_attack_score = hand_tuned_rule_score(df)
    results["hand_tuned_rule"] = summarize("hand-tuned rule (energygate.cpp fallback)", y_all, rule_attack_score)
    results["hand_tuned_rule"]["per_label"] = per_label_flagged(df, rule_attack_score, threshold=0.5)

    # 3. Retrained on these real traces, leave-one-session-out, with and without RSSI.
    for tag, cols in (("with_rssi", FEATURES_WITH_RSSI), ("without_rssi", FEATURES_NO_RSSI)):
        y, score, per_session = leave_one_session_out_scores(df, cols)
        key = f"retrained_{tag}"
        results[key] = summarize(f"retrained, leave-one-session-out ({tag})", y, score)
        results[key]["per_session"] = per_session
        results[key]["features"] = cols
        results[key]["per_label"] = per_label_flagged(df, score, threshold=0.5)

    os.makedirs(os.path.dirname(a.out), exist_ok=True)
    with open(a.out, "w") as f:
        json.dump(results, f, indent=2, default=str)

    print(f"rows={results['rows']}  sessions={results['sessions']}")
    print(f"label counts: {results['label_counts']}\n")
    for key in ("simulated_trained_shipped", "hand_tuned_rule", "retrained_with_rssi", "retrained_without_rssi"):
        r = results[key]
        print(f"{r['model']:<48} n={r['n']:<6} AUC={r['auc']:.4f}  TPR@1%FPR={r['tpr_at_1pct_fpr']:.4f}")
    print(f"\nwrote {a.out}")


if __name__ == "__main__":
    main()
