# Review: contracts/ fixtures and firmware/ (2026-11-03)

Scope: (1) validate the fixtures against `contracts/*.schema.json` and the
CONTRACT.md event table; (2) review `firmware/` for buffer-handling,
concurrency and protocol/contract mismatches. firmware/, ml/ and console/ were
read only. Each finding names its owner stream. The only file changed outside
this report is `contracts/CONTRACT.md` (host spelling), with a CHANGELOG entry.

Method: a jsonschema (draft 2020-12) script over every Event, EnergySample and
incident in `console/frontend-kit/fixtures/` (byte-identical to
`console/web/public/fixtures/`). Firmware was reviewed by reading it. Host unit
tests were built with g++ (`305 passed, 0 failed`). A host proof-of-concept
against `sentinel_proto` confirmed F1.

## 1. Fixtures vs contract

**Schema validation: 0 failures.** That covers 13 events (`events.json` 11,
`scan_examples.json` 2) and 600 energy samples. All incident `event_ids`
resolve, and the incident's techniques/layers match its events. Severity and
technique match the CONTRACT.md table for every event type, including
`gate_decision` (challenge→low, drop→medium). Energy samples have monotonic
`ts`, and `volts*amps` agrees with `power_mw` to within 10% on every row.

The schemas cannot catch these (owner: console):

| # | Fixture | Issue |
|---|---|---|
| X1 | `events.json` evt-0001, `scan_examples.json` evt-0012 | MailGuard events carry 3 `reasons`. Per CHANGELOG 2026-09-19, MailGuard events carry `reasons: []`. The demo shows a Why panel the real service never fills. |
| X2 | `energy.json` | Synthetic samples with no `source: "sim"`. `energy.schema.json` defines that flag so the UI can say SIMULATED (CLAUDE.md rule 4). Add it to each sample, or make sure fixture mode is always labelled. |
| X3 | `status.json` | `"mode": "none"` and `"link": "attack"` sit alongside `gate_decision` events from field-1. Real firmware only reports challenges and drops under `DEFENSE gate`/`cookie`/`ratelimit`; in `none` everything is SPEND. Cosmetic, but the demo story is inconsistent. |

## 2. Contract gaps (owner: console / contracts)

Not changed, because each needs the owner's decision:

- **C1 `attack_detected` technique is "by kind" with no mapping.** The fixture
  uses `T1692.002` for `replay_campaign`. The firmware sends `technique: null`
  for every kind (gateway `main.cpp:282`). The schema accepts both. Write the
  kind→technique table down, or say null is expected.
- **C2 `gate_decision` cardinality.** event.schema.json's `$comment` says "one
  per admission decision". field-1 rate-limits reports (`field_node/main.cpp:263`,
  `GATE_REPORT_MIN_INTERVAL_MS=200`; it always sends on an action change or a
  budget-exhausted edge) to save battery. So the console's event count is a
  lower bound. The exact counts only appear in the encrypted DATA
  `StatsPayload`, which the gateway prints as `LOG` (ignored by the console).
  Either the contract says "sampled", or the gateway emits the counts.
- **C3 `trace.hs_fail` semantics.** The schema says "handshakes that failed
  signature/level checks". The gateway also adds every AES-GCM tag failure on
  DATA (`gateway/main.cpp:560`) and every forged-id HELLO. So `hs_fail`
  double-counts `auth_fail`, and FieldGuard sees the same signal under two
  features.
- **C4 Mesh wire format is not in the contract.** `types.h` says "Message
  types, per contracts/CONTRACT.md", but CONTRACT.md has no such section. That
  is fine if it stays firmware-internal, but then the comment should point at
  `packet.h`/`gate_msgs.h`.
- **C5 (fixed) `localhost` in CONTRACT.md "Ports"** contradicted the repo rule.
  It now says `127.0.0.1`; see CHANGELOG 2026-11-03.

## 3. Firmware findings (owner: firmware)

Severity is the effect on the demo or the experiment. "Spoofable" means the
15-byte header is in clear and fragments are unauthenticated: the GCM tag
covers only the reassembled DATA message, and handshake messages are
authenticated only after reassembly. Any board can claim any `sender` byte.

### High

**F1. Gateway `Reassembler` can be exhausted remotely (DoS, and likely a heap
abort).** `gateway/main.cpp:642-648` feeds every multi-fragment DATA frame from
any sender into the shared `g_reasm`. RESPONSE reassembly uses the same table.
`Reassembler::feed` (`fragment.cpp`) has three problems:
- It refuses new streams once 8 are in flight. Every fragment refreshes the
  stream's 3 s timeout, so 8 spoofed DATA frames with `frag_n>=2`, re-sent
  every <3 s, block every RESPONSE. No handshake completes.
- It sizes streams from the attacker's `frag_n` with no total cap: 8 × 254 ×
  235 B ≈ 477 kB. On an ESP32 with a 48-90 kB crypto stack reserved, that
  `std::vector` growth exhausts the heap, which aborts and reboots the board.
- A single fragment with the same (sender, epoch, seq) and a different `frag_n`
  erases an in-flight stream (`fragment.cpp:72-76`). Epoch and seq of the
  pending RESPONSE are visible on air.

The host PoC shows all three: 8 streams and 477,520 B buffered, the legit
fragment 0 rejected, and the legit stream deleted by one `frag_n=15` frame.

Fix:
- Reassemble only DATA from `g_session.peer` with `hdr.epoch == g_session.epoch`.
- Give RESPONSE its own one-slot reassembler, keyed to `g_att`.
- Reject `frag_n` above `ceil(max_expected_len / 235)` per message type.
- On a `frag_n` mismatch, drop the new fragment instead of erasing the stream.

field-1 is safer because it reassembles only admitted HELLO sets (2 slots).
But in `DEFENSE none` every enrolled-id HELLO is admitted, and the sender byte
is spoofable, so the same rules apply: check `frag_n == ceil(HELLO_LEN/235)`
at fragment 0.

**F2. field-1 overwrites the HELLO buffer while the crypto task reads it.**
`field_node/main.cpp:439-441` does `memcpy(g_hello_buf, ...)` and `g_job = ...`
*before* `crypto_task_submit()` checks busy. With `kMaxAdmitted = 2`, a second
admitted set can complete while the first handshake is running. The running
`responder_handle_hello` then verifies a torn buffer and fails as
BAD_SIGNATURE/hs_fail. Under an insider or flood run, that means a legitimate
gateway handshake fails because of attacker traffic, which inflates "legit
connect %" losses for the wrong reason. Fix: `if (crypto_task_busy()) { busy_drop++; return; }`
before the copy. Also, `g_resp` and `g_await` are written by the crypto task
while the loop may be inside `responder_handle_confirm(g_resp, ...)` (line 447).
A second admitted HELLO during the 4 s await clobbers the pending responder
state.

**F3. Tamper never reaches the console.** field-1 detects
case_opened/moved/voltage_anomaly but only `Serial.print`s a LOG line
(`field_node/main.cpp:231-238`). It has no serial link during a run and sends
no mesh message for it. No firmware path emits a `tamper`-layer EVT, so the
4th layer (fixture evt-0010, incident stage "physical") cannot happen on real
hardware. It needs a mesh message (like GATE_REPORT) that the gateway turns
into `case_opened`/`moved`/`voltage_anomaly`, severity critical, node field-1.

### Medium

**F4. Gateway session install races with the loop.** `job_handle_response`
(crypto task, `gateway/main.cpp:366-381`) rewrites `g_session` with no lock:
keys, epoch, `replay.reset()` on a `std::map`. Meanwhile the loop task may be
inside `session_open()` on the same `Session` (`on_data`). Concurrent
`std::map` erase and insert is undefined behaviour, and can corrupt the heap.
A torn key read yields BAD_TAG, which emits a spurious `handshake_rejected`
(high, T0830) EVT. Fix: build the new session in a local, hand it to the loop
through a flag (as `g_result` already does), and swap it in from the loop.

**F5. EVT floods on the serial link are unthrottled.** These paths print one
EVT per received frame with no rate limit:
- `replay_rejected` (`:552`)
- `handshake_rejected` on BAD_TAG (`:561`)
- `handshake_rejected` on a forged field-1 HELLO (`:607`)

Only the forged-gateway-id path is throttled (2 s). At 115200 baud a ~300 B
line takes ~26 ms, so a few hundred spoofed frames/s stall the loop on
`Serial`, overflow the 24-deep RX queue (inflating `loss_pct`) and flood the
console. Throttle these the same way and count them in the trace instead.

**F6. Unvalidated floats from GATE_REPORT go straight into the EVT.**
`emit_gate_decision` (`gateway/main.cpp:188-192`) copies `prob_real`,
`budget_j` and `budget_max_j` from an unauthenticated, spoofable 16-byte
payload. A NaN, `>1` or negative value fails event.schema (`score` 0..1,
`budget_j >= 0`), so the console 422s it. ArduinoJson prints NaN/Inf as
non-JSON or null, depending on config. Clamp or reject before emitting. The
same spoofing lets any board inject fake `gate_decision`/`budget_exhausted`
events and send CONTROL to switch field-1 to `DEFENSE none`
(`field_node/main.cpp:500-505`). That is acknowledged as "lab rig, not
authenticated" in the header, but it belongs in the paper's threat-model
limits.

**F7. One forged CONFIRM or RESPONSE kills a handshake.** field-1's
`on_confirm` clears `g_await.active` on *any* frame that matches peer, epoch
and seq, even when `responder_handle_confirm` then fails (`:448`). All three
values are on air in clear, so one forged frame per attempt prevents every
session. Clear the await only on success, or on the deadline. On the gateway,
the RESPONSE path has the same problem through F1's first-writer and
`frag_n`-mismatch behaviour.

**F8. `jitter_ms` is always 0.** Nothing calls
`TraceWindowCounters::add_jitter()`, so every TRC row carries `jitter_ms: 0`.
FieldGuard (`ml/sentinel_ml/field_model.py` FEATURE_ORDER[9]) trains on a dead
feature. Either compute it, or tell ML so its reports do not imply the feature
carries signal.

### Low

- **F9. `rssi_var` can go slightly negative,** and trace.schema says
  `minimum: 0`, so the console drops the row. `trace.h` and `link_window.cpp`
  compute `E[x²] − mean²` with `mean` rounded to float. Replaying that
  arithmetic in numpy for 2000 samples (1999 × −83 dBm, 1 × −84) gives
  −8.8e-5. A 5 s window sees that many frames only under a heavy flood. Fix:
  keep the mean in double and clamp at 0.
- **F10. `to_contract_attack_kind` falls back to `"unknown"`,** which is
  outside the `details.kind` enum and would 422. It is unreachable with today's
  rule classifier. A swapped-in ML export that returns another int would hit
  it. Map unknown classes to "no event".
- **F11. `LABEL <x>` is copied unvalidated** (`gateway/main.cpp:477-482`) into
  every TRC row's `label`, which is an enum in the schema. A typo turns the
  whole recording into dropped rows. Validate against the 5 labels and keep the
  previous one otherwise.
- **F12. NRG lines are internally inconsistent.** `power_mw` is the 1 s mean,
  but `volts`/`amps` are the last instantaneous sample
  (`monitor/main.cpp:235-238`). A consumer computing V·I gets a different
  number. On the ADS1115 rig, a slightly negative single-ended read gives
  `volts < 0`, which fails `minimum: 0`. Send mean V and mean I, and clamp
  volts at 0.
- **F13. `rekey` is emitted when the gateway sends CONFIRM,** not when field-1
  installs the session. A lost CONFIRM still shows "New post-quantum session
  established".
- **F14. `EnergyBudget::tick` stops refilling after `millis()` wraps** (49.7
  days), because `now <= last` returns without resyncing. This is irrelevant
  for demo runs.
- **F15. Unused or stale code paths.** `lockout_sender` is `[[maybe_unused]]`
  and never called, so `g_locked_out` is never set. The changelog's "the
  gateway keeps ... lockout (beat 5)" is not what the code does. The
  `energygate.cpp` stand-in computes `hs_fail/(hs_per_s+hs_fail)`, mixing a
  rate with a count.

## 4. Checked and fine

- Header parse bounds-checks length, version, type and `frag_i < frag_n`.
- HELLO, RESPONSE and CONFIRM lengths are checked exactly in `pqc_handshake.cpp`.
- AEAD authenticates before the replay window advances (`msg_io.cpp`).
- Nonces are unique per key: fresh keys per handshake, and `tx_seq` resets with them.
- The RX callback only queues frames; the TX path is mutex-protected.
- EnergyGate features use the ML `FEATURE_ORDER`.
- The `DEFENSE` and `MODE` vocabularies match CONTRACT.md, including `SLOW_DRIP`.
- `gate_decision` severities match the table, and events carry `"node": "field-1"`.
- `rekey.level` maps to 512/768 by build level.
- Board `ts` is uptime, which the console rewrites.

## 5. Suggested order

F1 → F2 → F3 → F4/F5 → F6/F7 → F8 → the rest. X1/X2 and C1-C3 are quick
decisions for the console stream.
