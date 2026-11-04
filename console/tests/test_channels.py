"""Detection Channels registry (api/channels.py) and the SMS Guard it serves.

Toggle tests run against a temp copy of channels/ so they never rewrite the
committed manifests. The SMS model itself is the committed one
(channels/sms/*.joblib); these tests check the console's handling of it, not
its held-out accuracy (that is channels/sms/eval_report.json).
"""
import json
import os
import shutil
import sys
import tempfile

import pytest

CONSOLE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, CONSOLE)
if "SENTINEL_DB" not in os.environ:          # another test module may have set it already
    _tmp = tempfile.mkdtemp(prefix="sentinelmesh-ch-")
    os.environ["SENTINEL_DB"] = os.path.join(_tmp, "test.db")
    os.environ["SENTINEL_TRACE_DIR"] = os.path.join(_tmp, "traces")

from fastapi.testclient import TestClient  # noqa: E402

from api import channels, config  # noqa: E402
from api.main import app  # noqa: E402

client = TestClient(app)

pytest.importorskip("sklearn")
pytest.importorskip("joblib")

SMISHING = "URGENT! You have WON a 1000 cash prize. Call 09061701461 now to claim, txt STOP to end"
LEGIT = "Hey are we still meeting for lunch at 1? I'll be a bit late"


@pytest.fixture(autouse=True)
def temp_channels(tmp_path, monkeypatch):
    """Point the registry at a copy of channels/*/manifest.json."""
    src = config.CHANNELS_DIR
    for entry in os.listdir(src):
        m = os.path.join(src, entry, "manifest.json")
        if os.path.isfile(m):
            os.makedirs(tmp_path / entry)
            shutil.copy(m, tmp_path / entry / "manifest.json")
    # the model's code stays where it is; only the manifests are copied
    monkeypatch.syspath_prepend(os.path.join(src, "sms"))
    monkeypatch.setattr(config, "CHANNELS_DIR", str(tmp_path))
    channels.load_channels()
    yield tmp_path
    monkeypatch.undo()
    channels.load_channels()


def classify(channel="sms", text=SMISHING):
    return client.post("/classify", json={"channel": channel, "text": text})


# -- registry ------------------------------------------------------------------

def test_lists_every_manifest_with_its_status():
    body = client.get("/channels").json()
    by_id = {c["id"]: c for c in body["channels"]}
    assert body["count"] == len(by_id)
    assert by_id["sms"]["status"] == "active" and by_id["sms"]["live_classify"] is True
    for dummy in ("whatsapp", "telegram", "voice"):
        assert by_id[dummy]["status"] == "dummy"


def test_also_mounted_under_api():
    assert client.get("/api/channels").json() == client.get("/channels").json()


def test_manifest_whose_id_disagrees_with_its_folder_is_ignored(temp_channels):
    os.makedirs(temp_channels / "rogue")
    (temp_channels / "rogue" / "manifest.json").write_text(json.dumps({"id": "sms2"}))
    (temp_channels / "broken").mkdir()
    (temp_channels / "broken" / "manifest.json").write_text("{not json")
    channels.load_channels()
    ids = {c["id"] for c in client.get("/channels").json()["channels"]}
    assert "sms2" not in ids and "rogue" not in ids and "broken" not in ids


def test_toggle_flips_enabled_and_persists_to_the_manifest(temp_channels):
    assert client.post("/channels/sms/toggle").json()["enabled"] is False
    on_disk = json.loads((temp_channels / "sms" / "manifest.json").read_text())
    assert on_disk["enabled"] is False
    assert client.post("/channels/sms/toggle").json()["enabled"] is True


def test_toggle_unknown_channel_is_404():
    assert client.post("/channels/nope/toggle").status_code == 404


# -- /classify -----------------------------------------------------------------

def test_obvious_smishing_is_flagged_with_reasons():
    r = classify()
    assert r.status_code == 200
    body = r.json()
    assert body["channel"] == "sms" and body["label"] == "smishing"
    assert 0.0 <= body["confidence"] <= 1.0
    assert 1 <= len(body["reasons"]) <= 3 and all(isinstance(x, str) for x in body["reasons"])


def test_ordinary_message_is_legitimate():
    body = classify(text=LEGIT).json()
    assert body["label"] == "legitimate"


def test_label_follows_the_manifest_threshold(monkeypatch):
    score = classify().json()["confidence"]
    monkeypatch.setitem(channels._channels["sms"]["metrics"], "threshold", min(1.0, score + 0.01))
    assert classify().json()["label"] == "legitimate"


def test_dummy_channel_is_refused_not_faked():
    r = classify("whatsapp")
    assert r.status_code == 400 and "dummy" in r.json()["detail"]


def test_reference_channel_without_live_classify_is_refused():
    assert classify("email").status_code == 400


def test_disabled_channel_is_refused():
    client.post("/channels/sms/toggle")
    r = classify()
    assert r.status_code == 400 and "disabled" in r.json()["detail"]


def test_unknown_channel_is_404():
    assert classify("carrier-pigeon").status_code == 404


@pytest.mark.parametrize("body", [
    {"channel": "sms"}, {"channel": "sms", "text": "   "}, {"channel": "sms", "text": 5},
    {"text": "hi"}, {"channel": "", "text": "hi"}, {"channel": ["sms"], "text": "hi"}, ["sms", "hi"],
])
def test_malformed_body_is_400(body):
    assert client.post("/classify", json=body).status_code == 400


def test_non_json_body_is_400():
    r = client.post("/classify", content=b"not json", headers={"Content-Type": "application/json"})
    assert r.status_code == 400


def test_missing_model_files_is_503_not_a_crash(monkeypatch):
    monkeypatch.setitem(channels._channels["sms"], "model_path", "channels/sms/missing.joblib")
    monkeypatch.delitem(channels._models, "sms", raising=False)
    r = classify()
    assert r.status_code == 503 and "train.py" in r.json()["detail"]


# -- sms_guard module ------------------------------------------------------------

def test_normalize_text_replaces_urls_and_numbers():
    sms_guard = channels._sms_guard()
    out = sms_guard.normalize_text("Visit https://bit.ly/x1 or www.evil.test call 0800123")
    assert "bit.ly" not in out and "evil" not in out and "0800123" not in out
    assert out.count("urltok") == 2 and "numtok" in out


def test_explain_returns_nothing_for_text_with_no_known_features():
    sms_guard = channels._sms_guard()
    vec, model = channels._load_model(channels._channels["sms"])
    assert sms_guard.explain(vec, model, "☃☃") == []


def test_oversized_text_is_refused_before_scoring(monkeypatch):
    # 2 MB of text took ~5 s on the event loop, blocking every other request
    monkeypatch.setattr(channels, "_load_model", lambda ch: pytest.fail("scored oversized text"))
    r = classify(text="free " * 400_000)
    assert r.status_code == 413


def test_text_at_the_limit_is_still_scored():
    assert classify(text="a" * channels.MAX_TEXT_CHARS).status_code == 200


def _point_sms_at(monkeypatch, model_path, vec_path):
    monkeypatch.delitem(channels._models, "sms", raising=False)
    monkeypatch.setitem(channels._channels["sms"], "model_path", model_path)
    monkeypatch.setitem(channels._channels["sms"], "vectorizer_path", vec_path)
    import joblib
    monkeypatch.setattr(joblib, "load", lambda p: pytest.fail(f"unpickled {p}"))


@pytest.mark.parametrize("where", ["absolute", "dotdot"])
def test_model_path_outside_the_model_dirs_is_refused(tmp_path_factory, monkeypatch, where):
    # joblib.load runs code: a manifest must not be able to name any pickle on disk
    outside = tmp_path_factory.mktemp("outside")
    for name in ("model.joblib", "vec.joblib"):
        (outside / name).write_bytes(b"not loaded")
    if where == "absolute":
        model, vec = str(outside / "model.joblib"), str(outside / "vec.joblib")
    else:
        model = os.path.relpath(outside / "model.joblib", config.REPO_DIR)
        vec = os.path.relpath(outside / "vec.joblib", config.REPO_DIR)
        assert model.startswith("..")
    _point_sms_at(monkeypatch, model, vec)
    r = classify()
    assert r.status_code == 503
    assert "outside the model directories" in r.json()["detail"]


def test_vectorizer_path_is_confined_too(tmp_path_factory, monkeypatch):
    outside = tmp_path_factory.mktemp("outside")
    (outside / "vec.joblib").write_bytes(b"not loaded")
    _point_sms_at(monkeypatch, "channels/sms/model.joblib", str(outside / "vec.joblib"))
    r = classify()
    assert r.status_code == 503 and "vectorizer_path" in r.json()["detail"]


def test_committed_manifests_point_inside_the_model_dirs():
    for ch in channels._channels.values():
        for key in ("model_path", "vectorizer_path"):
            if ch.get(key):
                channels._model_file(ch, key)   # raises if outside
