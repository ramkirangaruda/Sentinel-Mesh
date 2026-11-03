"""Detection Channels registry: console-local (not contracts/ surface), the
same way v4.py's controls and frontend.py's /api/scan/* are.

Answers the "can the system detect a different channel, like SMS?" question
live: MailGuard and FileGuard are wrapped as reference entries so the panel
shows them, without touching either. SMS Guard is a real, independently
trained classifier (channels/sms/, built by channels/sms/train.py against
the UCI SMS Spam Collection) plugged in purely by dropping a manifest.json
next to a model.joblib/vectorizer.joblib -- no code here is SMS-specific.
WhatsApp/Telegram/Voice are clearly-labeled dummy entries: placeholder
metrics, no model, /classify refuses them outright.

Mounted twice by main.py -- root and /api -- like v4.py.

Endpoints:
    GET  /channels                 every channel + its enabled state + metrics
    POST /channels/{id}/toggle     flips `enabled`, persists to that channel's
                                    manifest.json -- a real effect: /classify
                                    checks the live in-memory value on every call
    POST /classify {channel, text} only for a channel with status=="active",
                                    live_classify==true, AND enabled==true;
                                    a dummy channel always gets 400, never a
                                    fabricated result
"""
import json
import os
import sys

from fastapi import APIRouter, HTTPException, Request

from . import config

router = APIRouter()

# id -> manifest dict (mutated in place on toggle, then written back to disk)
_channels: dict[str, dict] = {}
# Longest text /classify will score. An SMS is 160 chars and a long
# concatenated one a few thousand; the char 3-5-gram vectorizer runs
# synchronously on the event loop, and 2 MB of text measured ~5 s there,
# stalling every other request (bridge posts included) meanwhile.
MAX_TEXT_CHARS = 5000

# id -> (vectorizer, model), loaded lazily on first /classify call and cached
_models: dict[str, tuple] = {}


def _manifest_path(channel_id: str) -> str:
    return os.path.join(config.CHANNELS_DIR, channel_id, "manifest.json")


def load_channels() -> None:
    """Scan channels/*/manifest.json. Called once at import time; a channel
    that doesn't have a manifest yet (e.g. SMS before train.py has been run)
    simply doesn't appear -- there is nothing dishonest to hide, so nothing
    is faked in its place."""
    _channels.clear()
    if not os.path.isdir(config.CHANNELS_DIR):
        return
    for entry in sorted(os.listdir(config.CHANNELS_DIR)):
        path = os.path.join(config.CHANNELS_DIR, entry, "manifest.json")
        if not os.path.isfile(path):
            continue
        try:
            with open(path, encoding="utf-8") as f:
                manifest = json.load(f)
        except (json.JSONDecodeError, OSError):
            continue
        if manifest.get("id") != entry:
            continue  # folder name and declared id must agree -- avoids a silent mismatch
        _channels[entry] = manifest


load_channels()  # populate at import time, same as everything else in api/


def _get_or_404(channel_id: str) -> dict:
    channel = _channels.get(channel_id)
    if channel is None:
        raise HTTPException(404, f"unknown channel: {channel_id}")
    return channel


# -- GET /channels ------------------------------------------------------------

@router.get("/channels")
def list_channels():
    return {"channels": [_channels[k] for k in sorted(_channels)], "count": len(_channels)}


# -- POST /channels/{id}/toggle -----------------------------------------------

@router.post("/channels/{channel_id}/toggle")
def toggle_channel(channel_id: str):
    channel = _get_or_404(channel_id)
    channel["enabled"] = not channel.get("enabled", False)
    with open(_manifest_path(channel_id), "w", encoding="utf-8") as f:
        json.dump(channel, f, indent=2)
    return channel


# -- POST /classify -------------------------------------------------------------

def _load_model(channel: dict):
    channel_id = channel["id"]
    if channel_id in _models:
        return _models[channel_id]

    model_path = os.path.join(config.REPO_DIR, channel["model_path"])
    vec_path = os.path.join(config.REPO_DIR, channel["vectorizer_path"])
    if not (os.path.isfile(model_path) and os.path.isfile(vec_path)):
        raise HTTPException(503, f"{channel_id}: model files not found -- run "
                                 f"channels/{channel_id}/train.py first")

    try:
        import joblib
    except ImportError:
        raise HTTPException(503, f"{channel_id}: scikit-learn/joblib are not installed in this environment "
                                 f"-- pip install -r console/requirements.txt")
    # The vectorizer pickle refers to functions defined in the channel's own
    # module (channels/<id>/<id>_guard.py), so that folder must be importable
    # *before* unpickling, not just before the first explain() call.
    channel_dir = os.path.join(config.CHANNELS_DIR, channel_id)
    if channel_dir not in sys.path:
        sys.path.insert(0, channel_dir)
    model = joblib.load(model_path)
    vec = joblib.load(vec_path)
    _models[channel_id] = (vec, model)
    return vec, model


def _explain(vec, model, text: str, top_k: int = 3) -> list[str]:
    # A channel that reaches here always has live_classify==true, which today
    # only ever means SMS Guard, so its own explain() (which knows how to
    # label a FeatureUnion's word__/char__ feature names) is reused rather
    # than duplicating that logic here. A second live channel would add
    # another case here, not change the /classify contract below.
    return _sms_guard().explain(vec, model, text, top_k=top_k)


def _sms_guard():
    sms_dir = os.path.join(config.CHANNELS_DIR, "sms")
    if sms_dir not in sys.path:
        sys.path.insert(0, sms_dir)
    import sms_guard
    return sms_guard


@router.post("/classify")
async def classify(request: Request):
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(400, "body must be JSON: {\"channel\": \"sms\", \"text\": \"...\"}")

    channel_id = body.get("channel") if isinstance(body, dict) else None
    text = body.get("text") if isinstance(body, dict) else None
    if not isinstance(channel_id, str) or not channel_id:
        raise HTTPException(400, "'channel' must be a non-empty string")
    if not isinstance(text, str) or not text.strip():
        raise HTTPException(400, "'text' must be a non-empty string")
    if len(text) > MAX_TEXT_CHARS:
        raise HTTPException(413, f"'text' is longer than {MAX_TEXT_CHARS} characters")

    channel = _get_or_404(channel_id)

    if channel.get("status") != "active" or not channel.get("live_classify"):
        raise HTTPException(400, f"{channel['display_name']} is not available in demo "
                                 f"-- it is a demo/dummy channel with no trained model")
    if not channel.get("enabled", False):
        raise HTTPException(400, f"{channel['display_name']} is currently disabled "
                                 f"(toggled off) -- classification is switched off with it")

    vec, model = _load_model(channel)
    score = float(model.predict_proba(vec.transform([text]))[:, 1][0])
    threshold = channel.get("metrics", {}).get("threshold", 0.5)
    is_positive = score >= threshold
    reasons = _explain(vec, model, text)

    return {
        "channel": channel_id,
        "label": "smishing" if is_positive else "legitimate",
        "confidence": round(score, 4),
        "reasons": reasons,
    }
