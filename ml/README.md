# SentinelMesh ML (MailGuard + FileGuard + FieldGuard)

Owned by the ML stream. Scores emails and files, and (once traces arrive)
classifies FieldGuard windows. Implements the ML side of
`contracts/CONTRACT.md` — every response is a contract `Event`.

## Setup

```
python -m venv .venv
.venv\Scripts\activate        # PowerShell: .venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

## 1. Confirm the brief's numbers

```
python scratch_audit/audit_and_baselines.py --data "path/to/security"
```

Reproduces `SentinelMesh_Project_Brief_v3.pdf`'s numbers (email random-split
vs leave-one-corpus-out, the padding red-team test, the malware group split).
`scratch_audit/` is a gitignored scratch copy of the starter kit — the real
pipeline lives in `sentinel_ml/` and `build_all.py`.

## 2. Build the benign third-party binary set (FileGuard de-biasing)

Until the team's own Program Files / phone binaries arrive, `ml/benign/`
is bootstrapped from ordinary Windows pip wheels and npm packages — never
malware, never anything executed:

```
cd benign
bash fetch_pip_wheels.sh      # pip download --only-binary=:all: win_amd64 AND win32
                               # for pkg_list_pip.txt (~107 packages), one at a time
                               # so a missing win32 wheel doesn't abort the batch
bash extract_new_wheels.sh    # unzip into extracted/, platform-tagged so
                               # same-named win_amd64/win32 packages don't collide

# a handful more npm Windows-native packages (see git history for the exact list)
npm pack @esbuild/win32-x64 @esbuild/win32-ia32 lightningcss-win32-x64-msvc ... \
  --pack-destination npm_downloads
# untar each .tgz into extracted/npm_<pkg>/

python build_benign_features.py   # -> features/thirdparty_features.csv
```

This produced 1,566 native `.pyd/.dll/.exe/.node` files across 198
packages. Replace with real Program Files binaries when the team collects
them; `build_all.py` picks up whatever is in
`benign/features/thirdparty_features.csv`.

## 3. Train MailGuard + FileGuard, write reports/metrics.json

```
python build_all.py --data "path/to/security"
python reports/make_charts.py
```

Writes `models/mailguard.joblib`, `models/fileguard.joblib`,
`demo/malicious_features.json` (held-out malware rows for the live demo —
**no live malware is ever downloaded or run**) and `reports/metrics.json`
+ `reports/charts/*.png`.

## 4. Run the scoring service

```
uvicorn service:app --host 0.0.0.0 --port 8001
```

```
curl http://127.0.0.1:8001/health
curl -X POST http://127.0.0.1:8001/score/email -H "Content-Type: application/json" \
  -d '{"text": "URGENT: verify your account now"}'
curl -X POST http://127.0.0.1:8001/score/file -F "file=@C:/Windows/System32/notepad.exe"
curl -X POST http://127.0.0.1:8001/score/file -H "Content-Type: application/json" \
  -d "{\"features\": $(python -c "import json;print(json.dumps(json.load(open('demo/malicious_features.json'))[0]))")}"
curl -X POST http://127.0.0.1:8001/score/eml -F "file=@some_message.eml"
```

`/score/eml` (multipart `.eml`) parses headers and an HTML-or-plain body,
scores the body with MailGuard, scores `.exe`/`.dll` attachments with
FileGuard, and returns `file_clean`-style Events with
`details.unsupported=true` for anything else — a list of Events sharing
one `details.message_id` so the console can group them into an incident.

## 5. Run the live-demo script

```
cd demo
python build_demo_fixtures.py --data "path/to/security"
python run_demo.py
```

Walks held-out malicious/legit emails (plus a padded red-team one),
held-out malicious file features, and real benign binaries through the
service, in the brief's demo order, and posts each Event to the console
if one is listening. See `demo/README.md`.

## 6. Phase 2: FieldGuard on-device model

Waits on `data/traces/*.jsonl` (one file per recording session, each line
a `Trace` row per the contract). Once present, one command:

```
make field-model
```

trains the decision tree and writes `export/field_model.h`, exposing
`int classify_window(const float* f)` with no runtime dependency, for the
ESP32 build. `make test-field-model` proves the same pipeline (train ->
C export -> `gcc` compile -> 500-row parity check) against synthetic
`SYNTH_`-labelled data in `ml/tests/` -- never a real result, see that
folder's docstrings.

## 7. Phase 3: EnergyGate on-device gatekeeper (brief v4)

Brief v4 adds a research claim: post-quantum crypto turns the battery into
the attack surface, so a tiny model runs *before* the handshake to decide
whether a stranger is worth the energy. EnergyGate scores that -- it does
not decide spend/challenge/drop itself, that policy lives on field-1
(firmware, `lib/sentinel_proto/gate_policy.h`) -- the battery-powered node it
protects -- which holds the live joule-budget state this model doesn't
have. To deploy a trained model, copy `export/energygate.h` to
`firmware/lib/sentinel_proto/include/sentinel_proto/energygate_model.h`; the
firmware picks it up automatically and feeds it features in this module's
`FEATURE_ORDER`. See `docs/v4_energy_split.md` for the full split.

Same wait condition and same data as Phase 2 -- `data/traces/*.jsonl`,
nothing new to record:

```
make energygate
```

trains the decision tree and writes `export/energygate.h`, exposing
`float energygate_score(const float* f)` -> probability the sender is
real, in `[0, 1]`. `make test-energygate` proves the pipeline (train -> C
export -> `gcc` compile -> 500-row parity check, float-tolerance based)
against the same synthetic generator Phase 2 uses -- see
`sentinel_ml/energygate.py`'s docstring for the exact feature set, the
binary real/not-real target (derived from the existing 5-class label, no
new ground truth needed), and a known gap: the brief's "time since this
sender's last attempt" signal has no matching Trace field, so `hs_per_s`
(handshake rate) stands in for it -- noted, not overclaimed as equivalent.

**Stopgap: a model trained on SIMULATED traces.** Until real recordings exist,
`make energygate-synthetic` trains the tree on `tests/generate_synthetic_traces.py`'s
hand-written generator (30 sessions), parity-checks the C export against sklearn
(gcc, 500 rows), and copies it into the firmware as `energygate_model.h`, so the
board runs a learned tree instead of the rule-based stand-in. The header carries a
**SIMULATED -- NOT A RESULT** banner and its metrics live in
`reports/energygate_synthetic_metrics.json` (flagged `SIMULATED`). It encodes our own
assumptions about attacks, so its accuracy is never quoted as a result. Compiled with
the ESP32 toolchain it is 191 bytes of flash and no static RAM (the rule-based
stand-in is 307). Known limit: on separable simulated data nearly every leaf is
exactly 0 or 1, so scores are close to binary and the policy's *challenge* band
(0.4-0.7) is effectively unused; real, overlapping traces are what would populate it.
Re-run `make energygate` on real traces and replace the header.

**Stretch, lowest priority** (brief's own cut order puts this first to
cut): physical-identity / radio-fingerprint separability -- can the
gateway tell two identical boards apart by RSSI/timing/jitter alone?

**Found a real blocker, not just a data-availability gap, while scoping
this**: `contracts/trace.schema.json`'s `node` field is a closed enum,
`["field-1", "gateway", "attacker"]` -- there is no `field-2`. Telling two
identical field-node boards apart requires recording them under distinct
identities in the first place, and the contract as it stands has nowhere
to put a second one. This is the same shape of gap firmware flagged for
the jamming class (`firmware/README.md`) -- a contract question, not
something to route around quietly. Raise widening the `node` enum (or a
separate `details.board_id` for this experiment only) with Claude 2 if the
team decides to actually attempt this; until then there's no script to
write here, since it would have nothing valid to run against. Given it's
already first in the brief's own cut order, this is a reasonable stretch
to leave un-started rather than build tooling around a schema gap that may
never get resolved.

## Model cards + explanations

`reports/model_cards.md`: each model's data, honest metrics and known
limits (the 64-bit blind spot, 2000-2008 email dates, a re-implemented
feature extractor, and more). `sentinel_ml/reasons.py`: the word/feature
-> plain-English map behind every `Event.reasons` entry.

## Optional: DistilBERT vs. TF-IDF

`notebooks/transformer_mailguard.ipynb` -- brief section 5's "strengthen
at the event" transformer experiment, meant for a free Colab/Kaggle GPU
(not run in this repo). See `notebooks/README.md`.

## Layout

```
sentinel_ml/       data.py, text.py, eml.py, mailguard.py, fileguard.py,
                    field_model.py, energygate.py, reasons.py, schemas.py (Event), pe_features.py
service.py          FastAPI: /health, /score/email, /score/file, /score/eml
build_all.py         trains MailGuard + FileGuard, writes reports/metrics.json
train_field_model.py the real field-model entrypoint (`make field-model`)
train_energygate.py  the real EnergyGate entrypoint (`make energygate`, phase 3, v4)
benign/              third-party benign binaries + build_benign_features.py
demo/                held-out fixtures + run_demo.py for the live demo
reports/             metrics.json, model_cards.md, charts/*.png (make_charts.py)
export/              field_model.h (phase 2), energygate.h (phase 3, v4) -- both C export, real traces only
tests/               synthetic field-model + energygate pipeline tests (never real results)
notebooks/           transformer_mailguard.ipynb (optional, GPU-only)
```
