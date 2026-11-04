"""v4: status, energy, experiment, demo controls, and the /api frontend shapes."""
import os
import sys
import tempfile
import time
import uuid

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if "SENTINEL_DB" not in os.environ:          # test_api.py may have set it already
    _tmp = tempfile.mkdtemp(prefix="sentinelmesh-v4-")
    os.environ["SENTINEL_DB"] = os.path.join(_tmp, "test.db")
    os.environ["SENTINEL_TRACE_DIR"] = os.path.join(_tmp, "traces")

from fastapi.testclient import TestClient  # noqa: E402

from api import config, energy, experiment, frontend, v4  # noqa: E402
from api.main import app  # noqa: E402

client = TestClient(app)


def now_ms() -> int:
    return int(time.time() * 1000)


def ev(type_, severity, layer="field", node="gateway", details=None, ts=None, score=None, technique=None):
    return {"id": str(uuid.uuid4()), "ts": ts or now_ms(), "layer": layer, "type": type_,
            "severity": severity, "score": score, "node": node, "technique": technique,
            "summary": type_, "reasons": ["r1"], "details": details or {}}


def sample(power_mw=84.0, battery_pct=80.0, ts=None, source=None):
    s = {"power_mw": power_mw, "volts": 3.86, "amps": power_mw / 3860, "battery_pct": battery_pct}
    if ts is not None:
        s["ts"] = ts
    if source:
        s["source"] = source
    return s


@pytest.fixture(autouse=True)
def reset():
    client.post("/reset")
    client.delete("/experiment")
    client.post("/recording/stop")
    yield


# -- /status: honest when there is no data -----------------------------------

def test_status_with_nothing_connected_is_offline_not_secure():
    s = client.get("/status").json()
    assert s["link"] == "offline"
    assert s["battery_pct"] is None and s["power_mw"] is None and s["projected_days"] is None
    assert s["budget_j"] is None and s["crypto_level"] is None
    assert {n["id"]: n["state"] for n in s["nodes"]} == {"field-1": "offline", "gateway": "offline"}


def test_status_link_states_follow_recent_events():
    client.post("/energy", json=sample())                 # something is alive
    client.post("/traces", json={"rssi_mean": -50})       # gateway heard from
    assert client.get("/status").json()["link"] == "secure"

    client.post("/events", json=ev("link_degraded", "low"))
    assert client.get("/status").json()["link"] == "degraded"

    client.post("/events", json=ev("handshake_rejected", "high", node="attacker", technique="T0830"))
    assert client.get("/status").json()["link"] == "attack"

    client.post("/events", json=ev("case_opened", "critical", layer="tamper", node="field-1"))
    s = client.get("/status").json()
    assert s["link"] == "tamper"
    assert {n["id"]: n["state"] for n in s["nodes"]}["field-1"] == "tamper"


def test_a_gate_drop_counts_as_attack_but_a_spend_does_not():
    client.post("/energy", json=sample())
    client.post("/events", json=ev("gate_decision", "info", details={"action": "spend"}, score=0.9))
    assert client.get("/status").json()["link"] == "secure"
    client.post("/events", json=ev("gate_decision", "medium", details={"action": "drop"}, score=0.05))
    assert client.get("/status").json()["link"] == "attack"


def test_status_reports_latest_budget_and_zero_after_exhaustion():
    client.post("/events", json=ev("gate_decision", "low", score=0.2,
                                   details={"action": "challenge", "budget_j": 12.5, "budget_max_j": 40}))
    s = client.get("/status").json()
    assert (s["budget_j"], s["budget_max_j"]) == (12.5, 40)
    client.post("/events", json=ev("budget_exhausted", "high"))
    assert client.get("/status").json()["budget_j"] == 0.0


def test_projected_days_uses_measured_draw_and_assumed_cell():
    client.post("/energy", json=sample(power_mw=512.0, battery_pct=50.0))
    s = client.get("/status").json()
    expected = round(config.BATTERY_WH * 3600 * 0.5 / 0.512 / 86400, 2)
    assert s["projected_days"] == expected
    assert s["projection_assumes_wh"] == config.BATTERY_WH


def test_crypto_level_comes_from_the_latest_rekey():
    client.post("/events", json=ev("rekey", "info", node="field-1", details={"level": 1024, "reason": "tamper"}))
    assert client.get("/status").json()["crypto_level"] == 1024


# -- /energy -----------------------------------------------------------------

def test_energy_sample_round_trip_and_uptime_ts_is_replaced():
    before = now_ms()
    r = client.post("/energy", json=sample(ts=12_345))
    assert r.status_code == 201 and r.json()["device_ts"] == 12_345
    got = client.get("/energy").json()["samples"]
    assert len(got) == 1 and got[0]["ts"] >= before and got[0]["power_mw"] == 84.0


def test_energy_sample_missing_power_is_rejected():
    assert client.post("/energy", json={"volts": 3.8, "amps": 0.02}).status_code == 422


def test_simulated_samples_are_flagged_everywhere():
    client.post("/energy", json=sample(source="sim"))
    assert client.get("/energy").json()["simulated"] is True
    assert client.get("/status").json()["simulated"] is True


def test_energy_since_filters_samples_and_markers():
    t = now_ms()
    client.post("/energy", json=sample(ts=t - 5000))
    client.post("/energy", json=sample(ts=t))
    got = client.get("/energy", params={"since": t - 1}).json()
    assert [s["ts"] for s in got["samples"]] == [t]


# -- controls -> serial lines --------------------------------------------------

def test_mode_sets_defense_line_and_marker():
    before = client.get("/control").json()["mode_version"]
    r = client.post("/mode", json={"mode": "gate"})
    assert r.json()["line"] == "DEFENSE gate"
    c = client.get("/control").json()
    assert c["mode_version"] > before and c["defense_line"] == "DEFENSE gate"
    assert "EnergyGate on" in [m["label"] for m in client.get("/energy").json()["markers"]]


def test_attack_uses_the_attacker_boards_existing_mode_vocabulary():
    expected = {"none": "MODE OFF", "loud": "MODE FLOOD", "slow_drip": "MODE SLOW_DRIP",
                "replay": "MODE REPLAY", "impersonate": "MODE IMPERSONATE", "weak_link": "MODE WEAK_LINK"}
    for profile, line in expected.items():
        assert client.post("/attack", json={"profile": profile}).json()["line"] == line
        assert client.get("/control").json()["attack_line"] == line


def test_bad_control_values_are_rejected():
    assert client.post("/mode", json={"mode": "shields_up"}).status_code == 400
    assert client.post("/attack", json={"profile": "nuke"}).status_code == 400


def test_everything_is_also_served_under_api():
    for path in ("/status", "/energy", "/experiment", "/control"):
        assert client.get("/api" + path).status_code == 200, path
    assert client.post("/api/mode", json={"mode": "cookie"}).status_code == 200


# -- experiment table ------------------------------------------------------------

def _finish_run_with_samples(condition, profile, mw, source=None):
    run = client.post("/experiment/run", json={"condition": condition, "profile": profile,
                                               "duration_s": 10}).json()
    start, end = run["started_ts"], run["ends_ts"]
    for k in range(10):                      # one sample a second across the run
        client.post("/energy", json=sample(power_mw=mw, ts=start + 500 + k * 1000, source=source))
    experiment.finalize_due(v4._conn, now=end + 1)
    return run


def test_experiment_starts_with_five_pending_rows():
    t = client.get("/experiment").json()
    assert [r["condition"] for r in t["rows"]] == ["no_attack", "undefended", "ratelimit", "cookie", "gate"]
    assert all(r["status"] == "pending" for r in t["rows"])


def test_running_a_condition_sets_defence_and_attack():
    client.post("/experiment/run", json={"condition": "gate", "profile": "slow_drip", "duration_s": 10})
    c = client.get("/control").json()
    assert (c["mode"], c["attack_profile"]) == ("gate", "slow_drip")
    row = {r["condition"]: r for r in client.get("/experiment").json()["rows"]}["gate"]
    assert row["status"] == "running"


def test_only_one_run_at_a_time():
    client.post("/experiment/run", json={"condition": "no_attack", "profile": "loud", "duration_s": 10})
    r = client.post("/experiment/run", json={"condition": "gate", "profile": "loud", "duration_s": 10})
    assert r.status_code == 409


def test_finished_run_reports_energy_from_its_own_samples():
    _finish_run_with_samples("undefended", "loud", mw=500.0)
    row = {r["condition"]: r for r in client.get("/experiment", params={"profile": "loud"}).json()["rows"]}
    u = row["undefended"]
    assert u["status"] == "done" and u["source"] == "measured"
    assert u["energy_j_per_hour"] == pytest.approx(500 / 1000 * 3600, rel=1e-3)
    assert u["projected_days"] == energy.projected_days(500.0, 100.0)
    # the console cannot see the legit client -- it must not make that up
    assert u["legit_connect_pct"] is None and u["legit_extra_delay_ms"] is None
    # the attacker is stopped when an attacked run ends
    assert client.get("/control").json()["attack_profile"] == "none"


def test_simulated_runs_are_labelled_and_the_note_says_so():
    _finish_run_with_samples("gate", "loud", mw=95.0, source="sim")
    t = client.get("/experiment").json()
    assert {r["condition"]: r for r in t["rows"]}["gate"]["source"] == "simulated"
    assert "SIMULATED" in t["note"]


def test_legit_client_numbers_come_from_posted_results():
    _finish_run_with_samples("cookie", "loud", mw=120.0)
    client.post("/experiment/result", json={"condition": "cookie", "profile": "loud",
                                            "legit_connect_pct": 97.0, "legit_extra_delay_ms": 120})
    row = {r["condition"]: r for r in client.get("/experiment").json()["rows"]}["cookie"]
    assert (row["legit_connect_pct"], row["legit_extra_delay_ms"]) == (97.0, 120)


def test_a_no_attack_run_becomes_the_baseline():
    _finish_run_with_samples("no_attack", "loud", mw=84.0)
    s = client.get("/status").json()
    assert s["baseline_mw"] == pytest.approx(84.0, abs=0.1)
    assert s["baseline_source"] == "no_attack experiment run"


def test_bad_experiment_requests_are_rejected():
    assert client.post("/experiment/run", json={"condition": "x", "profile": "loud"}).status_code == 400
    assert client.post("/experiment/run", json={"condition": "gate", "profile": "x"}).status_code == 400


# -- /api frontend shapes (frontend-kit/src/types.ts) ----------------------------

def test_api_events_is_a_bare_list_of_contract_events():
    client.post("/events", json=ev("replay_rejected", "medium", technique="T1692.002"))
    got = client.get("/api/events", params={"since": 0, "limit": 200}).json()
    assert isinstance(got, list) and len(got) == 1
    assert set(got[0]) == {"id", "ts", "layer", "type", "severity", "score", "node",
                           "technique", "summary", "reasons", "details"}


def test_api_incidents_carry_kit_stages():
    t = now_ms()
    client.post("/events", json=ev("email_malicious", "high", layer="mail", node=None, ts=t,
                                   technique="T1566.001"))
    client.post("/events", json=ev("case_opened", "critical", layer="tamper", node="field-1", ts=t + 1000))
    inc = client.get("/api/incidents").json()
    assert isinstance(inc, list) and len(inc) == 1
    assert inc[0]["stages"] == {"inbox": "hit", "endpoint": "clear", "field": "clear", "physical": "hit"}
    assert inc[0]["escalated_by"]


def test_api_scan_reports_a_dead_ml_service_as_503(monkeypatch):
    monkeypatch.setattr(config, "ML_URL", "http://127.0.0.1:9")
    r = client.post("/api/scan/email", json={"text": "hello"})
    assert r.status_code == 503


def test_api_scan_stores_what_the_ml_service_returns(monkeypatch):
    scored = ev("email_malicious", "high", layer="mail", node=None, score=0.97, technique="T1566.001")
    monkeypatch.setattr(frontend, "_ml", lambda path, **kw: scored)
    r = client.post("/api/scan/email", json={"text": "URGENT verify your account"})
    assert r.status_code == 200 and r.json()[0]["id"] == scored["id"]
    assert client.get("/events").json()["events"][-1]["id"] == scored["id"]


def test_api_scan_rejects_an_ml_event_that_breaks_the_contract(monkeypatch):
    monkeypatch.setattr(frontend, "_ml", lambda path, **kw: {"id": "x", "ts": 1, "layer": "mail"})
    assert client.post("/api/scan/email", json={"text": "hi"}).status_code == 502


def _fake_file_ml(monkeypatch):
    calls = []

    def fake(path, **kw):
        calls.append(kw["files"]["file"])
        return ev("file_clean", "info", layer="file", node=None, score=0.03)
    monkeypatch.setattr(frontend, "_ml", fake)
    return calls


def test_scan_file_over_the_size_cap_is_413_and_never_reaches_ml(monkeypatch):
    calls = _fake_file_ml(monkeypatch)
    monkeypatch.setattr(config, "MAX_UPLOAD_BYTES", 1024)
    r = client.post("/api/scan/file", files={"file": ("big.exe", b"\0" * 4096)})
    assert r.status_code == 413 and "limit" in r.json()["detail"]
    assert calls == []


def test_scan_file_cap_also_holds_without_content_length(monkeypatch):
    calls = _fake_file_ml(monkeypatch)
    monkeypatch.setattr(config, "MAX_UPLOAD_BYTES", 1024)
    boundary = "xyz"
    body = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"big.exe\"\r\n"
            f"Content-Type: application/octet-stream\r\n\r\n").encode() + b"\0" * 4096 + \
           f"\r\n--{boundary}--\r\n".encode()

    def chunked():                       # a generator body is sent chunked, no Content-Length
        for i in range(0, len(body), 512):
            yield body[i:i + 512]
    r = client.post("/api/scan/file", content=chunked(),
                    headers={"content-type": f"multipart/form-data; boundary={boundary}"})
    assert r.status_code == 413
    assert calls == []


def test_scan_file_under_the_cap_is_proxied_intact(monkeypatch):
    calls = _fake_file_ml(monkeypatch)
    monkeypatch.setattr(config, "MAX_UPLOAD_BYTES", 64 * 1024)
    data = bytes(range(256)) * 16
    r = client.post("/api/scan/file", files={"file": ("ok.exe", data)})
    assert r.status_code == 200
    assert calls == [("ok.exe", data)]


def test_reset_keeps_finished_experiment_rows_but_drops_a_running_one():
    """Reset happens right before the pitch; the table was recorded before it."""
    _finish_run_with_samples("undefended", "loud", mw=500.0)
    client.post("/experiment/run", json={"condition": "gate", "profile": "loud", "duration_s": 10})
    client.post("/reset")
    rows = {r["condition"]: r for r in client.get("/experiment").json()["rows"]}
    assert rows["undefended"]["status"] == "done"
    assert rows["gate"]["status"] == "pending"


def test_reset_clears_demo_state():
    client.post("/energy", json=sample())
    client.post("/attack", json={"profile": "loud"})
    client.post("/reset")
    assert client.get("/energy").json()["samples"] == []
    assert client.get("/control").json()["attack_profile"] == "none"
