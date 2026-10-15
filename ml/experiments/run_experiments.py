"""Experiments that stress-test the shipped MailGuard / FileGuard claims.

Nothing here touches models/ or reports/metrics.json; results go to
reports/experiments.json so the shipped numbers stay reproducible.

    python experiments/run_experiments.py fileguard --data <security>
    python experiments/run_experiments.py mailguard --data <security>
    python experiments/run_experiments.py chars     --data <security>
    python experiments/run_experiments.py hardening --data <security>

fileguard  Shortcut ablation: retrain without ImageBase (and the other top-gain
           columns) and measure detection at 0.1% false alarms, plus false
           alarms on HELD-OUT third-party packages (the shipped
           thirdparty_false_alarm=0.0 is measured on binaries it trained on).
mailguard  Leave-one-corpus-out at a threshold tuned the way production tunes it
           (<=2% false alarms on in-distribution validation data), against the
           plain 0.5 the shipped LOCO numbers use, and against an oracle
           threshold tuned on the held-out corpus itself.
chars      Word TF-IDF vs word + character n-grams, under a stronger padding
           attack than the shipped one.
hardening  Leave-one-corpus-out for the padding-hardened recipes (none / shipped
           append-only / broader sandwich+interleaved), which the shipped LOCO
           numbers never measured.
"""
import argparse
import json
import os
import sys
import time

import numpy as np
import pandas as pd
from sklearn.metrics import roc_auc_score, roc_curve
from sklearn.model_selection import GroupShuffleSplit, train_test_split

HERE = os.path.dirname(os.path.abspath(__file__))
ML = os.path.dirname(HERE)
sys.path.insert(0, ML)

from sentinel_ml import fileguard, mailguard  # noqa: E402
from sentinel_ml.data import (EMAIL_CORPORA, load_emails, load_malware,  # noqa: E402
                              malware_feature_columns, malware_groups)

OUT = os.path.join(ML, "reports", "experiments.json")
BENIGN_CSV = os.path.join(ML, "benign", "features", "thirdparty_features.csv")


def save(section, data):
    res = json.load(open(OUT)) if os.path.exists(OUT) else {}
    res[section] = data
    with open(OUT, "w") as f:
        json.dump(res, f, indent=2, default=str)
    print(f"\n-> wrote '{section}' to {OUT}")


def tpr_at(y, s, fpr_target):
    fpr, tpr, _ = roc_curve(y, s)
    return float(np.interp(fpr_target, fpr, tpr))


# --------------------------------------------------------------------------
# FileGuard: shortcut ablation
# --------------------------------------------------------------------------
def fileguard_ablation(data):
    m = load_malware(data)
    cols = malware_feature_columns(df=m)
    X, y = m[cols], m["label"]
    groups = malware_groups(X)
    tr, te = next(GroupShuffleSplit(n_splits=1, test_size=0.2, random_state=fileguard.SEED).split(X, y, groups=groups))
    Xtr, ytr = X.iloc[tr].reset_index(drop=True), y.iloc[tr].reset_index(drop=True)
    Xte, yte = X.iloc[te].reset_index(drop=True), y.iloc[te].reset_index(drop=True)
    B, pkg = fileguard.load_thirdparty_benign(BENIGN_CSV, cols)

    configs = {
        "full (shipped recipe)": [],
        "- ImageBase": ["ImageBase"],
        "- ImageBase, Subsystem": ["ImageBase", "Subsystem"],
        "- top-5 gain cols": ["ImageBase", "Subsystem", "VersionInformationSize",
                              "MajorOperatingSystemVersion", "CheckSum"],
    }
    pk = np.array(sorted(pkg.unique()))
    results = {}
    for name, drop in configs.items():
        t0 = time.time()
        use = [c for c in cols if c not in drop]
        w = fileguard.THIRDPARTY_SAMPLE_WEIGHT

        # 1) dataset group-split detection, model trained with ALL third-party rows (production recipe)
        Xa = pd.concat([Xtr[use], B[use]], ignore_index=True)
        ya = pd.concat([ytr, pd.Series(0, index=range(len(B)))], ignore_index=True)
        wa = np.r_[np.ones(len(Xtr)), np.full(len(B), w)]
        mdl = fileguard._fit(Xa, ya, sample_weight=wa)
        s = mdl.predict_proba(Xte[use])[:, 1]
        thr = fileguard.threshold_for_max_fpr(yte.values, s, 0.001)

        # 2) HELD-OUT-package false alarms at that recipe's own tuned threshold (3 package splits)
        rng = np.random.default_rng(0)
        fa = []
        for _ in range(3):
            rng.shuffle(pk)
            half = set(pk[: len(pk) // 2])
            intr = pkg.isin(half).values
            Xb = pd.concat([Xtr[use], B[use][intr]], ignore_index=True)
            yb = pd.concat([ytr, pd.Series(0, index=range(int(intr.sum())))], ignore_index=True)
            wb = np.r_[np.ones(len(Xtr)), np.full(int(intr.sum()), w)]
            mb = fileguard._fit(Xb, yb, sample_weight=wb)
            sb = mb.predict_proba(Xte[use])[:, 1]
            tb = fileguard.threshold_for_max_fpr(yte.values, sb, 0.001)
            fa.append(float((mb.predict_proba(B[use][~intr])[:, 1] >= tb).mean()))

        results[name] = dict(
            n_features=len(use),
            auc=round(float(roc_auc_score(yte, s)), 5),
            detection_at_0p1pct_fpr=round(tpr_at(yte, s, 0.001), 4),
            detection_at_1pct_fpr=round(tpr_at(yte, s, 0.01), 4),
            heldout_pkg_false_alarm_mean=round(float(np.mean(fa)), 4),
            heldout_pkg_false_alarm_per_split=[round(a, 4) for a in fa],
            insample_thirdparty_false_alarm=round(float((mdl.predict_proba(B[use])[:, 1] >= thr).mean()), 4),
        )
        print(f"{name:28s} {results[name]}   [{time.time() - t0:.0f}s]", flush=True)
    save("fileguard_shortcut_ablation", results)


SEEDS = [42, 1, 2, 3, 4]


def fileguard_clusters(data, k=300):
    """Held-out-CLUSTER split: cluster files by feature similarity and hold out
    whole clusters. The shipped split only groups *identical* feature vectors,
    so near-duplicates (same malware family, rebuilt) can sit on both sides."""
    from sklearn.cluster import MiniBatchKMeans
    from sklearn.preprocessing import QuantileTransformer
    m = load_malware(data)
    cols = malware_feature_columns(df=m)
    X, y = m[cols], m["label"]
    Z = QuantileTransformer(n_quantiles=200, random_state=0).fit_transform(X)
    cl = MiniBatchKMeans(n_clusters=k, random_state=0, n_init=3, batch_size=4096).fit_predict(Z)
    B, _ = fileguard.load_thirdparty_benign(BENIGN_CSV, cols)
    results = {}
    for split_name, groups in [("exact-duplicate groups (shipped)", malware_groups(X).values),
                               (f"held-out clusters (k={k})", cl)]:
        for name, drop in [("all 54 features", []),
                           ("- top-5 gain cols", ["ImageBase", "Subsystem", "VersionInformationSize",
                                                  "MajorOperatingSystemVersion", "CheckSum"])]:
            use = [c for c in cols if c not in drop]
            runs = []
            for seed in SEEDS:
                tr, te = next(GroupShuffleSplit(n_splits=1, test_size=0.2, random_state=seed).split(X, y, groups=groups))
                Xtr, ytr = X.iloc[tr].reset_index(drop=True), y.iloc[tr].reset_index(drop=True)
                Xte, yte = X.iloc[te].reset_index(drop=True), y.iloc[te].reset_index(drop=True)
                Xa = pd.concat([Xtr[use], B[use]], ignore_index=True)
                ya = pd.concat([ytr, pd.Series(0, index=range(len(B)))], ignore_index=True)
                wa = np.r_[np.ones(len(Xtr)), np.full(len(B), fileguard.THIRDPARTY_SAMPLE_WEIGHT)]
                s = fileguard._fit(Xa, ya, sample_weight=wa).predict_proba(Xte[use])[:, 1]
                runs.append((tpr_at(yte, s, 0.001), tpr_at(yte, s, 0.01), float(roc_auc_score(yte, s))))
            a = np.array(runs)
            r = dict(seeds=SEEDS,
                     detection_at_0p1pct_fpr_mean=round(float(a[:, 0].mean()), 4),
                     detection_at_0p1pct_fpr_std=round(float(a[:, 0].std()), 4),
                     detection_at_0p1pct_fpr_per_seed=[round(float(v), 4) for v in a[:, 0]],
                     detection_at_1pct_fpr_mean=round(float(a[:, 1].mean()), 4),
                     auc_mean=round(float(a[:, 2].mean()), 5))
            results[f"{split_name} | {name}"] = r
            print(f"{split_name:34s} | {name:18s} {r}", flush=True)
    save("fileguard_cluster_split", results)


# --------------------------------------------------------------------------
# MailGuard: LOCO at a production-style threshold
# --------------------------------------------------------------------------
def mailguard_loco(data):
    em = load_emails(data)
    em["t"] = em["text"].str.slice(0, 3000)
    results = {}
    for src in EMAIL_CORPORA:
        t0 = time.time()
        a, b = em[em.source != src], em[em.source == src]
        a_tr, a_val = train_test_split(a, test_size=0.15, stratify=a.label, random_state=0)
        vec, mdl = mailguard.fit(a_tr.t, a_tr.label)
        thr = mailguard.threshold_for_max_fpr(a_val.label.values, mailguard.predict_proba(vec, mdl, a_val.t), 0.02)
        sb = mailguard.predict_proba(vec, mdl, b.t)
        yb = b.label.values
        r = dict(tuned_threshold=round(thr, 4),
                 recall_at_0p5=round(float((sb[yb == 1] >= 0.5).mean()), 4),
                 recall_at_tuned=round(float((sb[yb == 1] >= thr).mean()), 4))
        if len(set(yb)) > 1:
            r.update(
                false_alarm_at_0p5=round(float((sb[yb == 0] >= 0.5).mean()), 4),
                false_alarm_at_tuned=round(float((sb[yb == 0] >= thr).mean()), 4),
                auc=round(float(roc_auc_score(yb, sb)), 4),
                oracle_recall_at_2pct_fa=round(tpr_at(yb, sb, 0.02), 4),
            )
        results[src] = r
        print(f"{src:15s} {r}   [{time.time() - t0:.0f}s]", flush=True)
    save("mailguard_loco_tuned_threshold", results)


# --------------------------------------------------------------------------
# MailGuard: word vs word+char under a stronger padding attack
# --------------------------------------------------------------------------
CHAR_CAP = 1000   # chars fed to the char branch; RAM is the constraint on this laptop


def _char_hash(texts, n_jobs=6):
    from joblib import Parallel, delayed
    from sklearn.feature_extraction.text import HashingVectorizer
    from scipy import sparse
    hv = HashingVectorizer(analyzer="char_wb", ngram_range=(3, 5), n_features=2 ** 19,
                           alternate_sign=False, norm=None, dtype=np.float32,
                           preprocessor=lambda s: mailguard.normalize_text(s)[:CHAR_CAP])
    texts = list(texts)
    chunks = [texts[i:i + 4000] for i in range(0, len(texts), 4000)]
    return sparse.vstack(Parallel(n_jobs=n_jobs)(delayed(hv.transform)(c) for c in chunks)).tocsr()


def _pad(texts, pool, rng, before, after):
    return np.array([
        " ".join(rng.choice(pool, before)) + f" {t} " + " ".join(rng.choice(pool, after))
        for t in texts])


class WordChar:
    """Word TF-IDF (production recipe) + char-n-gram TF-IDF, one logistic regression."""

    def __init__(self, use_char):
        self.use_char = use_char

    def _x(self, texts, fit=False):
        from scipy import sparse
        if fit:
            self.vec = mailguard.build_vectorizer()
            xw = self.vec.fit_transform(texts)
        else:
            xw = self.vec.transform(texts)
        if not self.use_char:
            return xw
        from sklearn.feature_extraction.text import TfidfTransformer
        xc = _char_hash(texts)
        if fit:
            self.tf = TfidfTransformer(sublinear_tf=True)
            xc = self.tf.fit_transform(xc)
        else:
            xc = self.tf.transform(xc)
        return sparse.hstack([xw, xc]).tocsr()

    def fit(self, texts, y):
        from sklearn.linear_model import LogisticRegression
        self.lr = LogisticRegression(C=8, max_iter=3000, solver="liblinear").fit(self._x(texts, fit=True), y)
        return self

    def proba(self, texts):
        return self.lr.predict_proba(self._x(texts))[:, 1]


def chars_experiment(data):
    em = load_emails(data)
    em["t"] = em["text"].str.slice(0, 3000)
    tr, rest = train_test_split(em, test_size=0.3, stratify=em.label, random_state=mailguard.SEED)
    val, te = train_test_split(rest, test_size=0.5, stratify=rest.label, random_state=mailguard.SEED)

    rng = np.random.default_rng(0)
    pool = tr[tr.label == 0].t.str.slice(0, 600).values
    mal = te[te.label == 1].sample(min(3000, int((te.label == 1).sum())), random_state=0).t.values
    legit = te[te.label == 0].t.values
    attacks = {
        "clean": mal,
        "shipped_attack_append_2x600": _pad(mal, pool, rng, 0, 2),
        "stronger_sandwich_3_before_3_after": _pad(mal, pool, rng, 3, 3),
    }
    sp = tr[tr.label == 1].sample(6000, random_state=1).t.values
    aug_t = list(tr.t) + list(_pad(sp, pool, rng, 0, 2))     # shipped adversarial recipe (append only)
    aug_y = list(tr.label) + [1] * len(sp)
    aug_t2 = aug_t + list(_pad(sp[:3000], pool, rng, 3, 3))  # + sandwich-padded copies
    aug_y2 = aug_y + [1] * 3000

    # Attacks NO variant is trained on (generated after the augmentation so the
    # numbers above stay reproducible). Layout differs from every training pad.
    def _interleave(texts):
        out = []
        for t in texts:
            parts = [" ".join(p) for p in np.array_split(np.array(t.split() or [""]), 4)]
            out.append(f" {rng.choice(pool)} ".join(parts))
        return np.array(out)

    attacks.update({
        "UNSEEN_append_6x600": _pad(mal, pool, rng, 0, 6),
        "UNSEEN_prepend_6x600": _pad(mal, pool, rng, 6, 0),
        "UNSEEN_interleaved_4_pieces": _interleave(mal),
    })

    results = {}
    variants = [("word (shipped recipe)", False, aug_t, aug_y),
                ("word + char", True, aug_t, aug_y),
                ("word, trained on sandwich padding too (CONTROL)", False, aug_t2, aug_y2),
                ("word + char, trained on sandwich padding too", True, aug_t2, aug_y2)]
    for name, use_char, at, ay in variants:
        t0 = time.time()
        mdl = WordChar(use_char).fit(at, ay)
        thr = mailguard.threshold_for_max_fpr(val.label.values, mdl.proba(val.t), 0.02)
        r = dict(threshold=round(thr, 4), legit_false_alarm=round(float((mdl.proba(legit) >= thr).mean()), 4))
        for an, x in attacks.items():
            r[f"recall_{an}"] = round(float((mdl.proba(x) >= thr).mean()), 4)
        results[name] = r
        print(f"{name:46s} {r}   [{time.time() - t0:.0f}s]", flush=True)
        del mdl
    save("mailguard_char_ngrams_and_stronger_padding", results)


def _interleave_pieces(texts, pool, rng, pieces):
    out = []
    for t in texts:
        parts = [" ".join(p) for p in np.array_split(np.array(t.split() or [""]), pieces)]
        out.append(f" {rng.choice(pool)} ".join(parts))
    return np.array(out)


def hardening_loco(data):
    """Leave-one-corpus-out for the PADDING-HARDENED recipes. The shipped LOCO
    numbers (and mailguard_loco above) use the un-hardened fit(), so the hardened
    models were never measured on an unseen corpus.

    none = no augmentation; shipped = append-only padded copies (what mailguard.train
    does); broader = shipped + sandwich + interleaved copies (tried, reverted)."""
    em = load_emails(data)
    em["t"] = em["text"].str.slice(0, 3000)
    results = {}
    for src in ["CEAS_08", "Enron", "Ling", "SpamAssasin"]:
        a, b = em[em.source != src], em[em.source == src]
        a_tr, a_val = train_test_split(a, test_size=0.15, stratify=a.label, random_state=0)
        yb = b.label.values
        pool = a_tr[a_tr.label == 0].t.str.slice(0, 600).values
        sp = a_tr[a_tr.label == 1].sample(min(6000, int((a_tr.label == 1).sum())), random_state=1).t.values
        for recipe in ("none", "shipped", "broader"):
            t0 = time.time()
            t, y = list(a_tr.t), list(a_tr.label)
            if recipe != "none":
                rng = np.random.default_rng(0)
                t += list(mailguard.pad_with_legit(sp, pool, rng)); y += [1] * len(sp)
            if recipe == "broader":
                rng2, n = np.random.default_rng(2), min(3000, len(sp))
                t += list(_pad(sp[:n], pool, rng2, 3, 3))
                t += list(_interleave_pieces(sp[n:2 * n] if len(sp) >= 2 * n else sp[:n], pool, rng2, 4))
                y += [1] * (len(t) - len(y))
            vec, mdl = mailguard.fit(t, y)
            thr = mailguard.threshold_for_max_fpr(a_val.label.values, mailguard.predict_proba(vec, mdl, a_val.t), 0.02)
            s = mailguard.predict_proba(vec, mdl, b.t)
            r = dict(tuned_threshold=round(thr, 3), auc=round(float(roc_auc_score(yb, s)), 4),
                     recall_at_tuned=round(float((s[yb == 1] >= thr).mean()), 4),
                     false_alarm_at_tuned=round(float((s[yb == 0] >= thr).mean()), 4),
                     oracle_recall_at_2pct_fa=round(tpr_at(yb, s, 0.02), 4))
            results[f"{src} | {recipe}"] = r
            print(f"{src:12s} {recipe:8s} {r}   [{time.time() - t0:.0f}s]", flush=True)
    save("mailguard_hardening_loco", results)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("which", choices=["fileguard", "clusters", "mailguard", "chars", "hardening"])
    ap.add_argument("--data", required=True)
    a = ap.parse_args()
    {"fileguard": fileguard_ablation, "clusters": fileguard_clusters,
     "mailguard": mailguard_loco, "chars": chars_experiment,
     "hardening": hardening_loco}[a.which](a.data)
