"""MailGuard: TF-IDF + logistic regression malicious-email detector.

Pipeline: normalize text (placeholder tokens) -> TF-IDF (1-2 grams) ->
LogisticRegression. Trained with adversarial padding augmentation so a
malicious email padded with ordinary text is still caught (brief section 5).
"""
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, f1_score, roc_auc_score, roc_curve
from sklearn.model_selection import train_test_split

from .data import EMAIL_CORPORA, load_emails
from .reasons import humanize_mail_reason
from .text import normalize_text

SEED = 42


def build_vectorizer() -> TfidfVectorizer:
    return TfidfVectorizer(
        preprocessor=normalize_text,
        ngram_range=(1, 2),
        min_df=3,
        max_features=200_000,
        sublinear_tf=True,
    )


def fit(texts, labels, vec: TfidfVectorizer = None):
    vec = vec or build_vectorizer()
    X = vec.fit_transform(texts)
    model = LogisticRegression(C=8, max_iter=3000, solver="liblinear").fit(X, labels)
    return vec, model


def predict_proba(vec, model, texts):
    return model.predict_proba(vec.transform(texts))[:, 1]


def tpr_at_fpr(y, scores, target_fpr):
    fpr, tpr, _ = roc_curve(y, scores)
    return float(np.interp(target_fpr, fpr, tpr))


def threshold_for_max_fpr(y, scores, max_fpr):
    """Highest-recall threshold whose false-alarm rate is <= max_fpr."""
    fpr, tpr, thr = roc_curve(y, scores)
    ok = fpr <= max_fpr
    if not ok.any():
        return float(thr[np.argmin(fpr)])
    best = np.argmax(np.where(ok, tpr, -1))
    return float(thr[best])


def pad_with_legit(texts, legit_pool, rng, n_chunks=2, chunk_len=600):
    pool = legit_pool if len(legit_pool) else np.array([""])
    return np.array([
        f"{t} " + " ".join(rng.choice(pool, n_chunks))
        for t in texts
    ])


def explain(vec, model, text, top_k=3):
    """Top-k tokens (by |coef * tfidf|) that drove the score, signed."""
    x = vec.transform([text])
    coef = model.coef_[0]
    idx = x.nonzero()[1]
    if len(idx) == 0:
        return []
    contrib = np.asarray(x[0, idx].todense()).ravel() * coef[idx]
    order = np.argsort(-np.abs(contrib))[:top_k]
    fn = vec.get_feature_names_out()
    return [humanize_mail_reason(fn[idx[p]], float(contrib[p])) for p in order]


def train(security_root: str, max_false_alarm: float = 0.02, seed: int = SEED):
    """Full MailGuard train + evaluate. Returns (vec, model, threshold, metrics)."""
    em = load_emails(security_root)
    em["t"] = em["text"].str.slice(0, 3000)

    tr, rest = train_test_split(em, test_size=0.3, stratify=em.label, random_state=seed)
    val, te = train_test_split(rest, test_size=0.5, stratify=rest.label, random_state=seed)

    metrics = {"email_dedup_rows": len(em), "per_corpus": em.groupby("source").label.agg(
        ["size", "sum"]).rename(columns={"size": "n", "sum": "malicious"}).to_dict("index")}

    # -- baseline (no adversarial augmentation), for the red-team comparison
    v0, m0 = fit(tr.t, tr.label)
    s0 = predict_proba(v0, m0, te.t)
    p0 = s0 >= 0.5
    metrics["email_random_split_baseline"] = dict(
        acc=round(accuracy_score(te.label, p0), 4),
        f1=round(f1_score(te.label, p0), 4),
        auc=round(roc_auc_score(te.label, s0), 4),
        legit_false_alarm=round(float(p0[te.label.values == 0].mean()), 4),
    )

    # -- leave-one-corpus-out: the honest generalisation number
    loco = {}
    for src in EMAIL_CORPORA:
        a, b = em[em.source != src], em[em.source == src]
        vv, mm = fit(a.t, a.label)
        sb = predict_proba(vv, mm, b.t)
        pb = sb >= 0.5
        r = dict(malicious_recall=round(float(pb[b.label.values == 1].mean()), 4))
        if b.label.nunique() > 1:
            r.update(
                acc=round(accuracy_score(b.label, pb), 4),
                auc=round(roc_auc_score(b.label, sb), 4),
                legit_false_alarm=round(float(pb[b.label.values == 0].mean()), 4),
            )
        loco[src] = r
    metrics["email_leave_one_corpus_out"] = loco

    # -- red-team: pad held-out malicious emails with legit text
    rng = np.random.default_rng(0)
    legit_pool = tr[tr.label == 0].t.str.slice(0, 600).values
    n_mal = min(3000, (te.label == 1).sum())
    mal = te[te.label == 1].sample(n_mal, random_state=0).t.values
    padded = pad_with_legit(mal, legit_pool, rng)
    legit = te[te.label == 0].t.values

    def redteam_report(vec, mdl):
        score = lambda X: predict_proba(vec, mdl, X) >= 0.5
        return dict(
            legit_false_alarm=round(float(score(legit).mean()), 4),
            recall_clean=round(float(score(mal).mean()), 4),
            recall_padded=round(float(score(padded).mean()), 4),
        )

    redteam = {"baseline": redteam_report(v0, m0)}

    # -- adversarial training: augment training malicious emails with padding
    n_sp = min(6000, (tr.label == 1).sum())
    sp = tr[tr.label == 1].sample(n_sp, random_state=1).t.values
    aug_t = list(tr.t) + list(pad_with_legit(sp, legit_pool, rng))
    aug_y = list(tr.label) + [1] * len(sp)
    v_final, m_final = fit(aug_t, aug_y)
    redteam["adversarially_trained"] = redteam_report(v_final, m_final)
    metrics["email_red_team_padding"] = redteam

    # -- threshold: tune on val (plain, non-padded) for at most max_false_alarm FPR
    s_val = predict_proba(v_final, m_final, val.t)
    threshold = threshold_for_max_fpr(val.label.values, s_val, max_false_alarm)

    # -- final held-out test at the tuned threshold, with the adversarially-trained model
    s_te = predict_proba(v_final, m_final, te.t)
    p_te = s_te >= threshold
    metrics["email_random_split_final"] = dict(
        threshold=round(threshold, 4),
        acc=round(accuracy_score(te.label, p_te), 4),
        f1=round(f1_score(te.label, p_te), 4),
        auc=round(roc_auc_score(te.label, s_te), 4),
        legit_false_alarm=round(float(p_te[te.label.values == 0].mean()), 4),
        malicious_recall=round(float(p_te[te.label.values == 1].mean()), 4),
    )

    return v_final, m_final, threshold, metrics
