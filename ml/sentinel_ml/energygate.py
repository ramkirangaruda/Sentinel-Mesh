"""Phase 3 (brief v4): EnergyGate -- a probability that a sender is real,
scored *before* spending energy on the full PQC handshake. Trains on the
same Trace rows as field_model.py (contracts/CONTRACT.md), using the
brief's "free signals" subset plus the three v4-optional fields
(battery_pct, frag_complete_pct, dup_pct).

Binary target, derived from the same `label` column field_model trains on
-- there is no separate "was this sender real" ground truth recorded yet.
`normal` and `weak_link` (a legit sender on a bad link) count as real (1);
`replay`, `flood`, `impersonation` count as not-real (0). Revisit if the
console starts recording gate outcomes directly.

Exports a *probability*, not a class: `float energygate_score(const float*
f)`. The spend/challenge/drop policy -- comparing this probability against
a live joule budget and the handshake's estimated cost -- is firmware's
job; it needs on-device state this model doesn't have. Keep that split
clean, see docs/v4_energy_split.md.

Known gap: the brief lists "time since this sender's last attempt" as a
free signal. Trace has no such per-sender field; `hs_per_s` (aggregate
handshake rate) is the closest available proxy and stands in for it here.
Say so in the model card -- don't overclaim it's the same thing.
"""
import glob
import json
import os

import numpy as np
import pandas as pd
from sklearn.tree import DecisionTreeClassifier

FEATURE_ORDER = [
    "hs_per_s", "hs_fail", "rssi_mean", "rssi_var", "loss_pct",
    "dup_pct", "frag_complete_pct", "battery_pct",
]
REAL_LABELS = {"normal", "weak_link"}

# v4-optional Trace fields (contracts/trace.schema.json): rows recorded
# before the v2-energy contract delta won't carry them. Fall back rather
# than dropping the row -- these defaults read as "healthy / no signal".
OPTIONAL_DEFAULTS = {"dup_pct": 0.0, "frag_complete_pct": 100.0, "battery_pct": 100.0}


def load_traces(trace_dir: str) -> pd.DataFrame:
    """One recording session per *.jsonl file; used as the eval group."""
    rows = []
    for path in sorted(glob.glob(os.path.join(trace_dir, "*.jsonl"))):
        session = os.path.splitext(os.path.basename(path))[0]
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                d = json.loads(line)
                d["session"] = session
                rows.append(d)
    return pd.DataFrame(rows)


def train(trace_dir: str, max_depth: int = 4, seed: int = 42, real_labels=None):
    """Train on all sessions; evaluate leave-one-recording-session-out.

    `real_labels` overrides REAL_LABELS -- used by the synthetic-data test
    pipeline (ml/tests/) with SYNTH_-prefixed labels, so a test run can
    never be mistaken for a real result.

    Returns (clf, metrics). Raises ValueError if no trace files exist yet,
    or if every row falls on the same side of real_labels.
    """
    real_labels = real_labels or REAL_LABELS
    df = load_traces(trace_dir)
    if df.empty:
        raise ValueError(f"no *.jsonl trace files found in {trace_dir} -- EnergyGate waits on recorded traces")

    for col, default in OPTIONAL_DEFAULTS.items():
        if col not in df.columns:
            df[col] = default
        else:
            df[col] = df[col].fillna(default)

    X = df[FEATURE_ORDER].values.astype(float)
    y = df["label"].isin(real_labels).astype(int).values
    sessions = df["session"].values

    if len(set(y)) < 2:
        raise ValueError("training data is all-real or all-not-real -- need both classes to fit a classifier")

    clf = DecisionTreeClassifier(max_depth=max_depth, random_state=seed).fit(X, y)

    per_session = {}
    for s in sorted(set(sessions)):
        te_mask = sessions == s
        tr_mask = ~te_mask
        if len(set(y[tr_mask])) < 2 or te_mask.sum() == 0:
            continue
        m = DecisionTreeClassifier(max_depth=max_depth, random_state=seed).fit(X[tr_mask], y[tr_mask])
        pred = m.predict(X[te_mask])
        per_session[s] = dict(n=int(te_mask.sum()), acc=round(float((pred == y[te_mask]).mean()), 4))

    metrics = dict(
        rows=len(df),
        sessions=sorted(set(sessions)),
        real_pct=round(float(y.mean()) * 100, 1),
        leave_one_session_out=per_session,
    )
    return clf, metrics


def _leaf_prob(tree, node):
    """P(class 1 / "real") at a leaf, from the tree's raw value counts."""
    counts = tree.value[node][0]
    total = counts.sum()
    return float(counts[1] / total) if total > 0 else 0.5


def _emit_node(node, tree, indent):
    left, right = tree.children_left[node], tree.children_right[node]
    if left == -1 and right == -1:
        return f"{indent}return {_leaf_prob(tree, node):.6f}f;\n"
    feat_idx = tree.feature[node]
    thr = tree.threshold[node]
    code = f"{indent}if (f[{feat_idx}] <= {thr:.6f}f) {{ /* {FEATURE_ORDER[feat_idx]} */\n"
    code += _emit_node(left, tree, indent + "    ")
    code += f"{indent}}} else {{\n"
    code += _emit_node(right, tree, indent + "    ")
    code += f"{indent}}}\n"
    return code


def export_c(clf: DecisionTreeClassifier, out_path: str, banner: list = None):
    """Write a self-contained header exposing
    `float energygate_score(const float* f)` -- probability the sender is
    real, in [0, 1]. Firmware compares this against its own joule budget
    and the handshake's estimated cost to pick spend/challenge/drop; that
    policy does not live here, see the module docstring.

    `banner` lines go in a comment at the top, e.g. to mark a model trained
    on simulated data so the header can never be mistaken for a real one."""
    body = _emit_node(0, clf.tree_, "    ")
    lines = ["/* Auto-generated by sentinel_ml/energygate.py -- do not edit by hand. */"]
    if banner:
        lines += ["/*"] + [f" * {b}" for b in banner] + [" */"]
    lines += ["#ifndef SENTINELMESH_ENERGYGATE_H",
              "#define SENTINELMESH_ENERGYGATE_H", ""]
    lines.append("/* f[] must hold these " + str(len(FEATURE_ORDER)) + " features, in order:")
    for i, name in enumerate(FEATURE_ORDER):
        lines.append(f" *   f[{i}] = {name}")
    lines.append(" */")
    lines.append("static inline float energygate_score(const float* f) {")
    lines.append(body.rstrip())
    lines.append("}")
    lines.append("")
    lines.append("#endif /* SENTINELMESH_ENERGYGATE_H */")
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w") as f:
        f.write("\n".join(lines) + "\n")
