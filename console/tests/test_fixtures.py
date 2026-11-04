"""The UI's fixture files (frontend-kit/fixtures, copied to web/public/fixtures)
must tell the same story the real system would, and label invented numbers.

Schema validity alone is not enough: every check below is something
contracts/*.schema.json accepts but the real producers never send.
"""
import filecmp
import json
import os

import pytest
from jsonschema import Draft202012Validator

CONSOLE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
KIT = os.path.join(CONSOLE, "frontend-kit", "fixtures")
WEB = os.path.join(CONSOLE, "web", "public", "fixtures")
CONTRACTS = os.path.join(os.path.dirname(CONSOLE), "contracts")


def load(name):
    with open(os.path.join(KIT, name), encoding="utf-8") as f:
        return json.load(f)


def schema(name):
    with open(os.path.join(CONTRACTS, name), encoding="utf-8") as f:
        return Draft202012Validator(json.load(f))


def all_events():
    scans = load("scan_examples.json")
    return load("events.json") + scans["email"] + scans["file"]


@pytest.mark.parametrize("name", sorted(os.listdir(KIT)))
def test_web_copy_matches_the_kit(name):
    assert filecmp.cmp(os.path.join(KIT, name), os.path.join(WEB, name), shallow=False)


def test_every_fixture_event_matches_the_event_schema():
    v = schema("event.schema.json")
    for e in all_events():
        assert not list(v.iter_errors(e)), e["id"]


def test_mailguard_fixture_events_carry_no_reasons():
    # CHANGELOG 2026-09-19: MailGuard reports a score and a verdict, no reasons.
    mail = [e for e in all_events() if e["layer"] == "mail"]
    assert mail
    assert all(e["reasons"] == [] for e in mail), [e["id"] for e in mail if e["reasons"]]


def test_energy_fixture_is_labelled_simulated():
    v = schema("energy.schema.json")
    energy = load("energy.json")
    assert energy["simulated"] is True
    for s in energy["samples"]:
        assert not list(v.iter_errors(s))
        assert s["source"] == "sim"


def test_status_fixture_is_labelled_simulated():
    assert load("status.json")["simulated"] is True


def test_experiment_fixture_numbers_are_labelled_simulated():
    for r in load("experiment.json")["rows"]:
        if r["energy_j_per_hour"] is not None:
            assert r["source"] == "simulated", r["condition"]


def test_status_defence_mode_can_produce_the_fixture_gate_decisions():
    # firmware decide_admission(): NONE always SPENDs; RATELIMIT only drops;
    # COOKIE only challenges; challenge AND drop together need GATE.
    can_produce = {"none": {"spend"}, "ratelimit": {"spend", "drop"},
                   "cookie": {"spend", "challenge"}, "gate": {"spend", "challenge", "drop"}}
    actions = {e["details"]["action"] for e in all_events() if e["type"] == "gate_decision"}
    mode = load("status.json")["mode"]
    assert actions <= can_produce[mode], (mode, actions)
