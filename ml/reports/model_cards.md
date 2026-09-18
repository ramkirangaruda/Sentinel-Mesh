# Model cards

Honest numbers and known limits for each model, in the same spirit as
brief section 12's Q&A prep. Exact metrics are in `reports/metrics.json`
(regenerate with `python build_all.py --data ...`); this file explains
what they mean and where they can mislead.

## MailGuard (email)

**What it is.** TF-IDF (1-2 word phrases, numbers/URLs/emails replaced
with placeholder tokens) + logistic regression, adversarially trained on
padded copies of malicious mail. Threshold tuned on held-out data for
<=2% false alarms.

**Data.** `CEAS_08`, `Enron`, `Ling`, `Nigerian_Fraud`, `SpamAssasin`
only -- `phishing_email.csv` and `emails.csv` are excluded because they
duplicate these five (confirmed by `audit_and_baselines.py`: 99.8% of
`emails.csv` is inside `Enron`). 75,631 deduplicated emails after dropping
exact duplicates.

**Honest metrics** (`email_random_split_final` vs
`email_leave_one_corpus_out` in `reports/metrics.json`):

| | accuracy | legit false alarm |
|---|---|---|
| Random split (70/15/15; numbers are on the 15% test slice) | ~98% | ~1.8% |
| Held out: CEAS_08 | 92.0% | 6.9% |
| Held out: Enron | 87.6% | 9.4% |
| Held out: Ling | 94.5% | 4.4% |
| Held out: SpamAssasin | 93.9% | 6.2% |
| Held out: Nigerian_Fraud | recall 99.2%* | -- |

\* Nigerian_Fraud is 100% malicious, so it has no legit-mail rate to report.

The random split is the number that looks good; leave-one-corpus-out is
the one to quote, because it's the only one that tests generalization to
mail the model's vocabulary has never seen.

**Known limits.**
- **The emails are old.** Enron is 2000-2002 internal corporate mail;
  CEAS_08 is a 2008 spam challenge. None of this reflects 2026 phishing
  style, brand impersonation, or QR-code/attachment-based lures. The
  brief's suggested fix -- a small "2026 reality check" set of 20-30
  recent phishing emails from team inboxes -- has not been built yet.
- **The label is mostly "spam," not narrowly "phishing."** All five
  corpora collapse spam, scams, and phishing into one `label=1`. A model
  tuned on this may not weight credential-phishing cues the same way a
  phishing-specific dataset would.
- **The 2% false-alarm target does not transfer to a new email source.**
  With the threshold tuned the production way (<=2% false alarms on
  in-distribution validation data) and applied to a held-out corpus, false
  alarms are 9.2% (CEAS_08), 25.9% (Enron), 7.5% (Ling), 12.3%
  (SpamAssasin). Even with the threshold tuned on the new corpus itself,
  recall at 2% false alarms is only 67-87%
  (`reports/experiments.json`, `mailguard_loco_tuned_threshold`). The 1.8%
  in the table above holds for mail like the training mail only.
- **Red-team gap (padding).** Padding a malicious email with ordinary text
  dropped recall from 99.3% to 15.8% (append-only, at 0.5); adversarial
  training on that attack recovers it to 79.1% at a small false-alarm cost
  (1.2% -> 1.5%). The ~20-point gap is real evasion headroom. Padding layouts
  the model was **not** trained on do worse: in `reports/experiments.json`
  (`mailguard_char_ngrams_and_stronger_padding`) the shipped recipe catches
  ~53% with 3 chunks before and after, ~54% with 6 appended, ~52% with 6
  prepended, ~73% when interleaved into 4 pieces.
- **We tried hardening against more layouts and reverted it.** Adding sandwich
  and interleaved padding to the training data lifted those unseen layouts to
  72-91%, but cost generalisation to email the model has not seen. On a held-out
  corpus, at a threshold tuned on in-distribution data, recall at a 2%
  false-alarm budget for CEAS_08 fell 69% (no hardening) -> 45% (shipped
  append-only hardening) -> 39% (broader hardening); SpamAssasin 87% -> 78% ->
  75%; AUC fell on 3 of 4 held-out corpora versus the shipped model. The extra
  ~12,000 padded "malicious" rows also shift the training prior and push the
  tuned threshold up (0.44 -> 0.51). The shipped model was kept. **Note the
  shipped padding hardening itself carries a cross-corpus cost versus an
  un-hardened model** (the same numbers: 69% -> 45% on CEAS_08); it was never
  measured before. `python experiments/run_experiments.py hardening` reproduces
  this.
- **Character n-grams did not help and were not adopted.** A word+char
  model looked more robust (91% on the shipped append attack) only because
  its char branch read just the first 1,000 characters, so trailing padding
  never reached it; prepended padding collapsed it to 11%. The gain came
  from training on more padding layouts, not from the extra features (a
  word-only control trained the same way matched it). See
  `mailguard_char_ngrams_and_stronger_padding` in `reports/experiments.json`.
- **Per-corpus class imbalance varies a lot** (Nigerian_Fraud is 100%
  malicious; CEAS_08 is ~56%; SpamAssasin ~30%), which is part of why
  leave-one-corpus-out numbers swing as much as they do.

**Explanations.** Top-3 TF-IDF tokens by `|coefficient x tfidf weight|`,
converted to plain English by `sentinel_ml/reasons.py` (placeholder
tokens and a curated phishing-cue-word list; anything else falls back to
the raw word).

## FileGuard (file)

**What it is.** LightGBM on the 54 PE header features from `malware.csv`,
debiased with benign third-party Windows binaries (never the team's own
Program Files files -- see "Data" below) at sample weight 20. Threshold
tuned on held-out data for <=0.1% false alarms.

**Data.** `malware.csv`, 138,047 rows (~70% malicious), `|`-separated.
`Name` and `md5` are dropped from the features (`Name` leaks the label --
malware entries are `VirusShare*` 100% of the time). 35,856 rows
(~26%) share an identical feature vector with another row, so splits are
grouped by feature-vector hash, never by row, or the same sample can leak
across train/test.

**Honest metrics** (`malware_group_split_final` in `reports/metrics.json`):
group-split accuracy 99.2%, **detection at a 0.1% false-alarm rate
98.94%** (matches the brief's reported 98.9%) -- report this rate, not
plain accuracy, since accuracy alone hides how conservative the
threshold is.

**The third-party bias, measured and fixed.** The dataset's "benign"
class all comes from one Windows install, so the dataset-only model
flags real third-party software it's never seen as malware at a high
rate: **40.5%** of 1,566 benign binaries pulled from 198 real pip/npm
Windows packages, held out by whole package (mean of 5 random
package-level splits; `thirdparty_experiment_mean_of_5.dataset_only` in
`reports/metrics.json`). Adding those same binaries to training,
upweighted (sample weight 20), cuts that to **0.44%**
(`plus_thirdparty_benign`), with malware detection essentially unchanged
(99.65% -> 99.67%). See `reports/charts/malware_thirdparty.png`.

**Known limits.**
- **64-bit blind spot.** Only 68 of 96,724 malicious samples are 64-bit
  (`malware_x64_files_by_class` in metrics.json); the model has almost no
  exposure to 64-bit malware and should be assumed weak there. Fixing
  this needs external 64-bit samples in the same 54-feature format, which
  depends on what the event rules allow.
- **Re-implemented feature extractor.** `pe_features.py` (used to score
  real files live, and to build the benign third-party set) is a
  from-scratch re-implementation using `pefile`, not the original
  extractor behind `malware.csv`. Values should line up, but small
  differences in entropy/resource calculations between implementations
  are possible and untested against the original extractor.
- **The benign third-party set, while now 1,566 files across 198
  packages (pip `win_amd64` + `win32` wheels for ~107 popular packages,
  plus npm), is still narrow.** It's built from pip/npm packages and
  Windows system binaries, not the team's own Program Files -- see
  `ml/README.md`'s benign-set section. The false-alarm rate on truly
  novel legitimate software in the wild may differ from what the
  held-out-package test estimates.
- **`ImageBase` dominates the gain, but the model does not depend on it.**
  It accounts for 74% of LightGBM's gain and alone gives ~0.94 AUC, a sign
  the dataset's classes differ in incidental ways (how they were
  compiled/linked). We retrained without it, and without the top-5 gain
  columns: detection at 0.1% false alarms is essentially unchanged
  (98.5% -> 98.1%, 5 seeds). Other columns carry the same signal, so this
  is not a single fixable shortcut. Still worth stress-testing against
  adversarially-built binaries.
- **Unseen malware families are much harder than the headline number.**
  The shipped split groups only *identical* feature vectors, so
  near-duplicates (same family, rebuilt) can sit on both sides. Holding out
  whole clusters of similar files (k-means, k=300, 5 seeds) drops
  detection at 0.1% false alarms from 98.5% +/- 0.3% to **88.1% +/- 7.2%**
  (range 74.6-95.9%), while AUC stays ~0.999. Quote the 88% for
  "malware unlike anything in training". Clusters are a proxy for families,
  not real family labels (`fileguard_cluster_split`).
- **The in-sample third-party number.** `thirdparty_false_alarm: 0.0` in
  `malware_group_split_final` is measured on binaries the final model
  trained on. The honest figure is the held-out-package one: ~0.2% at the
  tuned threshold (3 package splits, `fileguard_shortcut_ablation`).

**Explanations.** Top-3 features by LightGBM `pred_contrib`, converted to
plain English by `sentinel_ml/reasons.py` (all 54 feature names are
mapped).

## FieldGuard (phase 2, on-device)

Not trained on real data yet -- the provided dataset has no radio/IoT
traffic. `sentinel_ml/field_model.py` trains a small (max_depth ~6)
decision tree on recorded `Trace` rows and exports it to C
(`export/field_model.h`, `int classify_window(const float* f)`) once
`data/traces/*.jsonl` exists (`make field-model`). The pipeline itself
(train -> C export -> gcc compile -> parity check) is verified against
synthetic data in `ml/tests/` -- **that synthetic accuracy is not a real
result** and is never written to this file or to `reports/metrics.json`.

The board currently runs a hand-written rule-based classifier with placeholder
thresholds (`firmware/.../field_model.h`), not this tree, so there is no measured
FieldGuard accuracy. The tree's features are the firmware's 10, in the firmware's
order; `window_ms` was removed from the feature list because it is the constant
5000 ms window and would have shifted every index against the board's
10-float vector. `tests/test_feature_order_matches_firmware.py` keeps the two in step.

## EnergyGate (phase 3, on-device) -- SIMULATED, not a result

**What it is.** A small decision tree (depth 5, 15 leaves) over 8 cheap signals
(`hs_per_s, hs_fail, rssi_mean, rssi_var, loss_pct, dup_pct, frag_complete_pct,
battery_pct`) that outputs the probability a sender is real, exported to C and
compiled into field-1's firmware. The spend/challenge/drop policy, joule budget
and cookie live in firmware (`gate_policy.h`), not here.

**Data: simulated.** No real traces exist yet (`console/data/traces/` is empty),
so this was trained on `tests/generate_synthetic_traces.py --hard`: 30 sessions,
3,600 windows, 63% "real". Hard mode makes the classes overlap (attack windows
are interpolated toward normal by Beta(2, 1.2), so many are only weakly
abnormal), adds multiplicative measurement noise and 3% label noise (the
console's `LABEL` is set by a human, so windows straddling a switch are
mislabelled). Those settings were fixed in advance, not tuned to a result. It
is still our own assumptions about attacks, so **nothing below is a measured
result**. The header carries a SIMULATED banner and every JSON/chart it writes
is flagged SIMULATED.

**Held-out evaluation (leave-one-session-out, on simulated data).**

| depth | AUC | log loss | Brier | calibration error (ECE) | accuracy @0.5 |
|---|---|---|---|---|---|
| 3 | 0.934 | 0.180 | 0.044 | 0.006 | 95.1% |
| 4 | 0.941 | 0.175 | 0.042 | 0.008 | 95.0% |
| **5 (shipped)** | 0.947 | 0.171 | 0.040 | 0.010 | 95.5% |

Depth was chosen by held-out log loss, capped at 5 to keep the on-device claim
(loss was still falling at 5). Scores are graded, not binary (leaf
probabilities range 0.00-1.00 with several mid values) and well calibrated on
simulated data. That calibration is a property of the generator, not evidence
it holds on real traffic.

**Operating-point sweep** (`reports/energygate_synthetic_sweep.json`,
`reports/charts/energygate_sweep_SIMULATED.png`). With the firmware's default
thresholds (spend >= 0.7, challenge >= 0.4), on held-out simulated windows:
98.7% of legitimate senders connect (1.7% delayed by a challenge) and the
attacker makes the node spend 7.7% of the energy it would undefended; 2.1% of
windows fall in the challenge band. It assumes a cookie challenge costs 5% of a
handshake (ASSUMED, not measured), that legitimate senders pass it and attackers
do not, and it is per-window, not a time simulation. It shows the *shape* of the
trade-off the mechanism offers.

**What it uses.** `hs_fail` (56% of importance) and `dup_pct` (39%) do almost
all the work; `loss_pct`, `hs_per_s`, `rssi_mean` carry a little; `battery_pct`,
`rssi_var` and `frag_complete_pct` are unused. `battery_pct` being unused is the
sanity check that mattered: it is a per-session constant in the generator, and
with few sessions a tree can latch onto it as a stand-in for session identity.

**Ablation: does it really come down to two features?** Yes, in this
simulation. Retraining with the shipped recipe (depth 5, same held-out-session
protocol; `experiments/energygate_ablation.py`,
`reports/energygate_synthetic_ablation.json`), out-of-fold:

| features | AUC | log loss | accuracy @0.5 |
|---|---|---|---|
| all 8 (shipped) | 0.947 | 0.171 | 95.5% |
| `hs_fail` + `dup_pct` only | 0.955 | 0.170 | 95.1% |
| the other 6 (no `hs_fail`, no `dup_pct`) | 0.880 | 0.387 | 82.9% |
| `hs_fail` only | 0.787 | 0.393 | 84.9% |
| `dup_pct` only | 0.801 | 0.462 | 80.0% |
| `battery_pct` only (leakage control) | 0.485 | 0.665 | 62.7% |

Two features match all eight, so the other six add nothing measurable here
(two features score marginally higher on AUC, 0.955 vs 0.947; that gap was not
tested for significance and should not be read as "fewer features is better").
Neither feature works alone, and the other six together
carry a weaker version of the same signal (AUC 0.88), so it is not literally
"two counters and nothing else". The battery control sits at chance (0.485), so
the tree is not cheating through the per-session constant. **This says how the
generator is built** (attacks produce failures and duplicates), not that real
attackers will; real recordings may lean on different signals. The honest reading
for the tiny on-device claim is that a tree on just those two features does about
as well in simulation, and that the value of learning from all eight has to be
shown on real traces.

**Verified.** The C export matches sklearn to 2e-7 on 500 boundary-stressing
rows (gcc parity check). Compiled with the ESP32 (Xtensa) toolchain the scoring
code is 423 bytes of flash and no static RAM (the rule-based stand-in is 307).
Inference *energy* is not estimated here; the INA219 rig has to measure it.
Firmware native tests pass with the model compiled in (288/288) and without it
(290/290).

**Known limits.**
- **Vantage-point caveat.** Training windows are recorded at the gateway, but the
  model scores at field-1 (see `contracts/CHANGELOG.md`). Irrelevant for
  simulated data, worth watching once real traces exist.
- **"Time since this sender's last attempt"** (a brief signal) has no Trace field;
  `hs_per_s` stands in for it and is not equivalent.
- **Weak signal plus failures is ambiguous by design.** A very weak link with many
  failed handshakes scores ~0.35 (undecided): a real weak link and an attacker
  look alike there, and that is what the challenge band is for.
- The hard-mode overlap is our guess at how messy real data is. Real recordings
  may be easier or much harder; only they can say.

## SMS Guard (detection channel, `channels/sms/`)

Not part of `ml/` (it lives in `channels/sms/` so a channel is self-contained),
but it is a shipped model, so it gets the same treatment. Its own numbers are
in `channels/sms/metrics.json`.

**What it is.** Word (1-2 gram) plus character (3-5 gram, word-bounded) TF-IDF
into a class-balanced logistic regression, numbers and URLs replaced by
placeholder tokens. Threshold tuned on a validation slice for <=3% false alarms.

**Data.** UCI SMS Spam Collection (CC-BY-4.0), 5,171 messages after exact-text
dedup, 12.7% spam. One stratified split: 3,515 train / 621 validation / 1,035
test (131 spam, 904 legitimate).

**Honest metrics** (held-out test, tuned threshold 0.2204; 95% Wilson
intervals computed from the confusion matrix):

| | value | 95% interval |
|---|---|---|
| Spam recall (126 of 131) | 96.2% | 91.4-98.4% |
| Legitimate false alarm (23 of 904) | 2.5% | 1.7-3.8% |
| Precision (126 of 149 flagged) | 84.6% | 77.9-89.5% |
| AUC | 0.996 | -- |

Precision is the number to watch. It is well below recall because spam is only
12.7% of messages, so even a small false-alarm rate produces a fair number of
false flags. This one split is at the pessimistic end; repeated cross-validation
(`channels/sms/evaluate.py`, `channels/sms/eval_report.json`; 5-fold x 3 repeats,
threshold re-tuned in every fold to the same <=3% target) gives:

| | mean +/- std | range over 15 folds |
|---|---|---|
| Spam recall | 95.7% +/- 2.5 | 90.8-99.2% |
| Legitimate false alarm | 1.5% +/- 0.9 | -- |
| Precision | 90.9% +/- 5.3 | 79.5-97.6% |

Quote the cross-validated figures with their range: roughly 1 flag in 11 is a
legitimate message on average, 1 in 6.5 on the shipped split. The script first
rebuilds the shipped split and model and confirms it reproduces `metrics.json`
exactly (same threshold, same confusion matrix), so the CV is about the shipped
recipe.

**Known limits.**
- **No held-out source.** Cross-validation shows the spread across random
  splits of this one collection; it does not test messages from a different
  source, and the collection is a single source. Unlike MailGuard there is no
  leave-one-corpus-out equivalent, so the 96% is a random-split number in the
  sense of the MailGuard section: expect it to fall on messages that do not
  resemble the collection.
- **The data is old and generic.** Roughly 2000s-era SMS, mostly UK and
  Singapore, and the label is plain "spam". Phone numbers, prices and premium
  short codes drive it. It has not seen 2020s smishing (parcel-redelivery links,
  bank OTP lures), and "smishing" in the console is that spam label, not a
  purpose-built phishing dataset.
- **Legitimate messages that contain digits are flagged about 5x as often.**
  Measured on out-of-fold predictions (repeat 0 of the cross-validation, every
  message scored by a model that never saw it, shipped threshold target):
  legitimate messages **with** a digit are flagged 6.0% of the time (43 of 715),
  those **without** 1.1% (43 of 3,803). The strongest global features are the
  number placeholder (`numtok`, `numtok numtok`) and the URL placeholder, which
  fits. The mirror image: spam without any digit is caught only 64% of the time
  (25 of 39; small sample), against 98% with a digit. So the model leans on
  "contains a number" as a spam cue. Probes in the console environment
  (scikit-learn 1.8.0, `POST /api/classify`): the rehearsed `legit_reminder`
  fixture in `channels/sms/fixtures.json` (a dentist appointment, "2:30pm")
  scores 0.895 and is **flagged as smishing**; "Your Amazon order 114-882 has
  shipped" scores 0.962 and "Your OTP is 482913. Do not share it with anyone."
  scores 0.396, both flagged. A casual message with a digit ("...around 7...", the
  `legit_friend` fixture) scores 0.021 and passes, and "Meeting moved to 3pm,
  room 204" scores 0.163 and passes, so a digit raises the risk without
  deciding it. Both rehearsed smishing fixtures are caught (0.632, 0.918). Four
  fixtures and three ad-hoc probes prove nothing statistically; they illustrate
  the measured pattern above, and the demo script should not claim all four
  rehearsed messages come out right.
- **The threshold is a precision/recall dial, and it cannot fix that message.**
  Cross-validated with the threshold re-tuned in every fold (same 15 fits):

  | false-alarm target for tuning | recall | false alarm | precision |
  |---|---|---|---|
  | <=3% (shipped) | 95.7% +/- 2.5 | 1.5% | 90.9% +/- 5.3 |
  | <=2% | 95.2% +/- 2.4 | 0.9% | 93.7% +/- 3.7 |
  | <=1% | 94.0% +/- 2.3 | 0.7% | 95.4% +/- 3.0 |

  A stricter target buys about 3-4 points of precision for 0.5-2 points of
  recall. The shipped model keeps the <=3% target (`manifest.json` unchanged); this
  is a measured option, not a change that has been adopted, for two reasons. The
  threshold `train.py` picks from its 621-message validation slice is unstable:
  across the 15 CV folds the tuned threshold ranges 0.14-0.64 at the shipped target
  and 0.19-0.67 at <=2% (std ~0.15), and on the shipped split it jumps from 0.22 to
  0.65 between the 3% and 2% targets. And a stricter value chosen now would also
  flip a rehearsed smishing fixture (`smishing_delivery`, 0.632) to a miss, which
  is exactly the kind of demo-driven tuning to avoid. The proper fix is to choose
  the threshold from out-of-fold scores over all the data rather than one small
  slice, then re-evaluate. Stopping the
  `legit_reminder` fixture specifically would need a threshold above 0.895, which
  on the shipped test split drops recall from 96.2% to 86.3%: far too high a
  price for one message.
- **Environment.** The pickles were built with scikit-learn 1.8.0
  (`console/requirements.txt`) while `ml/requirements.txt` pins 1.9.1. Use a
  console environment installed from `console/requirements.txt` (verified: live
  `/classify` works there, and the evaluation script reproduces the shipped
  confusion matrix exactly); without scikit-learn the API returns a 503 for
  `/classify` rather than a fake result.
