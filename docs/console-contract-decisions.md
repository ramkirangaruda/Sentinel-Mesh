# Contract gaps: decisions needed (console stream, 2026-11-04)

For: the human deciding contract changes. From: Claude 2 (console + contracts).
Source: review C1-C4 in `docs/review-contracts-firmware.md` (branch
`claude/contracts-firmware`). I checked each claim against the code on
`master` (edbca30). **Nothing in `contracts/` has changed.** Each item needs your
call. Any shape change then gets a `CHANGELOG.md` entry announced to all three
streams.

## C1. `attack_detected` technique is "by kind", with no mapping written down

**Confirmed.** CONTRACT.md's event table gives the technique as "by kind" and
lists no kinds. The gateway sends `nullptr` for every kind
(`firmware/src/gateway/main.cpp:211`, `:282`). The console mocks pick their own
IDs: `replay_campaign` → T1692.002 (`tools/mock_events.py`),
`impersonation` → T0830 (`tools/mock_events.py`), `handshake_flood` → T0830
(`tools/mock_serial.py`). So the demo shows techniques on stand-in data, and
real hardware shows none. The incident's technique list then also differs
between the two.

Options:
- **A.** Add a kind → technique table to CONTRACT.md, and have firmware send it.
  This needs a firmware change.
- **B.** Write the same table in CONTRACT.md, but have the console fill
  `technique` from `details.kind` when it arrives as null. The table is
  console-side, so firmware needs no change, and the schema already accepts both.
- **C.** State that null is expected, and remove the techniques from the mocks.

**Recommendation: B.** It is one table and one normalisation step, the same
kind of step as the console's `ts` rewrite. Mocks and hardware then agree.
Before freezing the table, check the IDs against ATT&CK for ICS, especially
`handshake_flood`. A flood is closer to a denial of service than to
adversary-in-the-middle (T0830).

## C2. `gate_decision` cardinality: "one per admission decision" is not what firmware does

**Confirmed.** The `$comment` in `event.schema.json` says "one per admission
decision". field-1 suppresses repeat reports within
`GATE_REPORT_MIN_INTERVAL_MS = 200` (`firmware/src/field_node/main.cpp:74`,
`:263`). It always reports a change of action and the edge where the budget
runs out. So the console's count of decision events is a lower bound. The
exact spend/challenge/drop counts reach the gateway only in the stats payload,
which it prints as a `LOG` line (`gateway/main.cpp:541`). The console ignores
that line.

Options:
- **A.** Contract says "sampled": at most one per 200 ms per field-1, plus every
  action change. Nobody quotes event counts as decision counts.
- **B.** Also add an optional `details.counts` (spend/challenge/drop since the
  last report) to `gate_decision`. This is additive, and firmware already has
  the numbers.
- **C.** Report every decision. This costs battery and serial bandwidth under
  flood, which defeats the purpose.

**Recommendation: A now, B if the paper needs decision rates.** For A, the
console changes nothing and the UI already shows a stream, not a total. The
experiment table's legit-connect numbers come from
`POST /experiment/result`, not from event counts, so they are unaffected.

## C3. `trace.hs_fail` double-counts `auth_fail`

**Confirmed.** `trace.schema.json` defines `hs_fail` as "handshakes that failed
signature/level checks". The gateway also increments it on every AES-GCM tag
failure on DATA (`gateway/main.cpp:560`) and on every forged-id HELLO
(`:585`, `:605`). Each of these also increments `auth_fail`. So FieldGuard
sees the same signal under two features. EnergyGate's `hs_fail` input inherits
the same inflation.

Options:
- **A.** Firmware follows the schema: `hs_fail` counts handshake verification
  failures only, and DATA tag failures go to `auth_fail` only. ML retrains on
  new traces.
- **B.** Change the description to match the firmware ("any authentication
  failure, handshake or data"). ML notes the overlap in its reports.
- **C.** Leave both as they are and only document the overlap.

**Recommendation: A.** The schema's meaning is the useful one: a handshake
failure and a forged data packet are different attacks. No traces have been
recorded on real hardware yet (see `console/CLAUDE.md`, "Waiting on other
streams"), so no real data is lost. Owner: firmware for the fix, ML to
retrain. The shape is unchanged.

## C4. "Message types" section referenced but missing

**Confirmed.** `firmware/lib/sentinel_proto/include/sentinel_proto/types.h:18`
says "Message types, per contracts/CONTRACT.md 'Message types'". CONTRACT.md
has no such section. The mesh wire format (header, HELLO/RESPONSE/CONFIRM/DATA,
GATE_REPORT, CONTROL) is used only between boards. No other stream parses it.

Options:
- **A.** Keep it firmware-internal: firmware changes the comment to point at
  `packet.h` / `gate_msgs.h`.
- **B.** Add a "Message types" section to CONTRACT.md, so the wire format
  becomes shared surface that needs CHANGELOG entries for every change.

**Recommendation: A.** Only firmware produces and consumes these messages.
Putting them in the contract would add announcement overhead with no second
consumer. The one-line comment fix belongs to firmware.

## Summary

| Gap | Recommendation | Who acts | Contract shape change |
|---|---|---|---|
| C1 | console fills technique from kind; table in CONTRACT.md | console (+ ATT&CK ID check) | prose only |
| C2 | document "sampled"; optional `details.counts` later | console (prose), firmware if B | prose now; additive field if B |
| C3 | firmware counts DATA tag failures in `auth_fail` only | firmware, then ML retrain | none |
| C4 | fix the comment in `types.h` | firmware | none |
