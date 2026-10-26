# Task for Ramkiran: `MODE FORGE` attacker mode (research rig, 2026-10-26)

Paste this whole file into your Claude session. Self-contained. Chaitanya has the boards and will flash and run
this on the INA219 energy rig at the end of tonight's run, so push it by ~06:00 on 2026-10-27 (after that the
borrowed INA219 goes back). This is for the team's own SentinelMesh lab setup: three ESP32 boards on one desk,
isolated ESP-NOW, measuring our own node's energy. All demo keys are committed test keys.

## Why
Measured on the rig (`paper/CONTEXT_2026-10-24.md`, "Finding 2"): the existing `FLOOD` and `ADAPTIVE_SPOOF` put
**random bytes** in the HELLO signature field. ML-DSA verify rejects a malformed signature during unpacking,
before the costly step, so our field node spends only ~1.7 ms on each and its power barely moves. That means our
runs do not yet show the energy asymmetry the paper claims.

A **structurally valid** signature (a genuine ML-DSA-65 signature produced once by the attacker's own enrolled
key, then reused) passes the format checks and makes the field node run the **full** verification (measured in E2:
26.2 ms, 3.2 mJ above idle) before it fails at the final step. So one signing operation on the attacker lets it
force the full check repeatedly. `MODE FORGE` reuses that one valid HELLO so the behaviour is visible on the rig.

## What to build
A new mode `FORGE` in `firmware/src/attacker/main.cpp`:
1. On entering `MODE FORGE`, build **one** HELLO once via the existing `job_make_signed_hello` path
   (`pqc::initiator_make_hello(..., demo_keys::SIG_SK_ATTACKER, ...)`), cache those `HELLO_LEN` bytes in a static
   buffer, and set a "template ready" flag. Do the signing on the crypto task, as the other signed modes do.
2. On each tick (reuse the `RATE`/`g_rate_hz` pacing like `tick_flood`), resend the cached bytes with a **fresh
   (epoch, seq)** each time via `send_hello_frames(static_cast<uint8_t>(NodeId::GATEWAY), template, HELLO_LEN,
   g_epoch++, g_seq++)`, so the replay guard sees a new HELLO every time. Do **not** re-sign and do **not**
   randomise the signature bytes. The signature stays valid in form; it just verifies against the gateway's key,
   which field-1 uses because the HELLO claims `NodeId::GATEWAY`, so verification runs to the end and fails.
3. Add `FORGE` to the `AttackMode` enum, `mode_name()`, the `MODE` parser, the boot help string, and the
   dispatch in the main tick. Keep `STATS` working (count attempts/frames as the other modes do).
4. Fix the stale comment at the top of the file: random-byte HELLOs are rejected cheaply during signature
   unpacking, before the full verify; only a structurally valid reused signature forces the full check.

HELLO layout (from `sentinel_pqc/pqc_handshake.h` and `pqc_handshake.cpp`): `HELLO_LEN = COOKIE_BYTES(8) +
NONCE_BYTES(16) + KEM_PK_BYTES + SIG_BYTES`; offsets `H_COOKIE=0, H_NONCE=8, H_PK=24, H_SIG=H_PK+KEM_PK_BYTES`.
Leave the cookie zeroed (`memset(template, 0, pqc::COOKIE_BYTES)`) like `tick_flood`, unless `ECHO on`, which the
existing CHALLENGE-handling code already covers.

## Tests (host, no hardware)
Add to `firmware/test/test_attacker/` and wire into `firmware/tools/run_native_tests.sh` (Ramkiran already added
cases there): the template is built once and its bytes do not change across sends; each send advances (epoch,seq);
the signature field is byte-for-byte identical between two sends (i.e. not re-randomised); `MODE OFF` clears the
template-ready flag. `bash firmware/tools/run_native_tests.sh` and `bash firmware/tools/run_pqc_tests.sh` stay
green. `pio run -e attacker` builds.

## Keep it clash-free
- Branch: work on **`paper/analysis-writing`** (yours). First `git fetch && git merge origin/paper/e5-grid-tooling`
  so you have tonight's energy data and the context notes.
- Edit only **`firmware/src/attacker/**`**, **`firmware/test/test_attacker/**`**, **`firmware/tools/run_native_tests.sh`**.
  Do not touch `firmware/lib/**`, `firmware/src/field_node/**`, the gateway, the contracts, or anything under
  `paper/tools/**` or `paper/data/**` (Chaitanya owns those and is running on them right now).
- Keep the serial interface exactly as named above (`MODE FORGE`, uppercase). Chaitanya's run script calls
  `--attacks FORGE`, which sends `MODE FORGE` verbatim; a different spelling breaks the run.
- Commit message style: `firmware: MODE FORGE (reused valid-form HELLO signature forces full verify)`. Push to
  `origin/paper/analysis-writing`, then tell Chaitanya the commit hash. He cherry-picks or merges that one commit
  to flash A; your branch and his stay separate until the final PRs.
- Do not change `platformio.ini` env names; `attacker` is what gets flashed.

## When it's pushed
Tell Chaitanya: "FORGE pushed on paper/analysis-writing, commit <hash>". He builds it, runs
`--defences none cookie gate --attacks FORGE --reps 5` on the rig (adds ~75 min to tonight), and reports
victim mJ per forged HELLO vs the attacker's ~one signing op. That is the number for the paper's asymmetry claim (C2).
