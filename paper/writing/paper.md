<!--
SentinelMesh paper draft (task S6, paper/WORK_SPLIT.md). Owner: person S.

CANONICAL SOURCE: paper/ieee/paper.tex (2026-10-31 decision). Two drafts had been developing in
parallel -- this file (detailed working notes, every number traced to its source) and the IEEE
submission draft, which already had the abstract, related work, conclusion and references this
file was still missing. paper.tex is now the one that gets submitted; its title and author list
(below) are authoritative. This file stays as supplementary detail -- the working-notes version
of every result, kept in sync with paper.tex's findings but not reformatted to match its compact
IEEE prose. When the two disagree on a number, paper.tex is right; fix this file to match, not
the other way round.

Markdown for now; convert to the venue's LaTeX template with pandoc once a venue is chosen.
Every number here cites the repo file it comes from. Markers:
  [TODO S2] / [TODO S3] / [TODO S5] / [TODO S7]  filled from that task's tables
  [CITE ...]                                     filled by S4 (paper/writing/related_work.md)
  SIMULATED / ESTIMATED / PLACEHOLDER            stay in the text until real data replaces them
-->

# EnergyGate: Defending Battery-Powered IoT Nodes Against Post-Quantum Handshake Exhaustion Attacks

*Title and author list as of `paper/ieee/paper.tex` (canonical). Authors: Ramkiran Garuda,
Chaitanya Patil, Adithya Binoj Nair (VIT SCOPE). This file's working title above
("The Battery, Not the Message...") and its earlier four-author byline are superseded.*

## Abstract

*(Ported from `paper/ieee/paper.tex`, the canonical source — fix there first, then copy here.)*

A battery-powered field device that accepts post-quantum handshakes pays for every request it
is asked to check, whether or not the request is genuine. We measure that cost on commodity
ESP32 microcontrollers running ML-KEM (FIPS 203) and ML-DSA (FIPS 204) over a broadcast ESP-NOW
mesh, through a calibrated high-side INA219 rig. At NIST level 3 the responder's share of one
handshake costs ≈14.9 mJ above idle; a forged HELLO carrying a structurally valid signature
forces a full ML-DSA-65 verification (≈3 mJ) before it fails. Over 120 s attacks (*n* = 5, 95 %
CI), an undefended insider raises the victim's power by +91.2 ± 3.3 mW and cuts legitimate
handshake success to 0.21; a single-signature forger adds +19.0 ± 1.4 mW. We present
*EnergyGate*, which decides at the first fragment of a HELLO — before reassembly and before any
public-key work — whether to spend, challenge or drop, using an eight-feature link score and a
joule token bucket. It removes the insider drain (+1.1 mW) without locking out the real gateway,
but an attacker that echoes the broadcast cookie under the *same* (epoch, seq) it was challenged
on still drains the victim (+13.0 mW under a cookie that binds to that exact header, down from an
unbound cookie's +16.0 mW — the fix makes the echo dearer for the attacker, not free). The joule
budget is what actually limits this: in 900 s echo attacks under our gate it empties and
admissions settle near the refill bound *r*/*c_h* = 2.5 s⁻¹, measured extra power falling from
+12.2 ± 4.3 to +5.5 ± 2.4 mW once it does — but only because our placeholder charge overcosts a
forged verify by ≈7×; at an honest cost the same bound would sit above this attacker's own rate
and never bind. A slow, one-per-minute attacker evades the score entirely and never drains the
budget either — its own cost is simply too small to matter. Our defences also protect energy, not
availability: the real gateway's success rate tracks the attacker's frame rate (49 % at 100
frames/s) whether or not the victim is spending any crypto cycles at all. Retrained on recorded
traces and evaluated by session, the gate's tree reaches AUC 0.95 and catches most adaptive
traffic the shipped model misses, though the shipped firmware still carries the original model.

## 1. Introduction

Post-quantum key exchange is arriving on constrained devices. ML-KEM (FIPS 203) and ML-DSA
(FIPS 204) run on a commodity ESP32 in milliseconds to tens of milliseconds per operation
(Section 6.1), so the question is no longer whether a microcontroller *can* run a signed
post-quantum handshake, but what it costs to let anyone *ask* it to.

Field devices in distribution grids, pipelines and environmental monitoring often run on a
battery and talk over a shared broadcast radio. A post-quantum handshake on such a device is
an expensive, unauthenticated-until-verified operation triggered by a message anyone in
radio range can send. At NIST level 3 a single HELLO is 4517 bytes, 20 ESP-NOW frames, and
checking it means an ML-DSA-65 verification; admitting it commits the device to an
encapsulation, a signature and a 19-frame response. The cryptography protects the message.
Nothing in it protects the battery.

This paper treats the battery as the attack surface. Our motivating scenario follows the
2015 attack on the Ukrainian grid, whose chain ran from phishing through malicious
attachments to the field network and physical access; we study the field-network step, where
an attacker within radio range of a battery-powered node wants to shorten its life or deny
service without breaking any cryptography.

Contributions:

- **C1, measured cost.** Energy per post-quantum operation and per handshake on real ESP32
  hardware with the radio on, through a calibrated high-side INA219 rig, at two parameter
  sets (ML-KEM-512 + ML-DSA-44, ML-KEM-768 + ML-DSA-65). [TODO S2: headline mJ per
  handshake.]
- **C2, the attack's exchange rate.** The victim-to-attacker energy ratio for flood, insider
  and slow-drip attackers under four defences (none, rate limit, cookie, EnergyGate), with
  repeated runs and 95 % confidence intervals. [TODO S3.]
- **C3, a budget-bounded learned gate.** EnergyGate decides at the first fragment of a HELLO,
  before reassembly and before any public-key work, whether to spend, challenge or drop,
  using an eight-feature link score and a joule token bucket. We show the bucket bounds the
  worst-case drain even when an adaptive attacker fools the score. [TODO S5/S7.]
- **C4, the artifact.** Firmware, rig description, calibration data, raw logs and the
  scripts that rebuild every table from them.

[CITE S4: one paragraph placing this against PQC-on-MCU energy work, handshake DoS work
and battery-exhaustion defences. No "first" claims unless S4's search supports them.]

## 2. Background

- **ML-KEM and ML-DSA.** [Short: FIPS 203/204, parameter sets used, key/ciphertext/signature
  sizes from Table 1. CITE.]
- **ESP-NOW.** Connectionless Wi-Fi-vendor frames, at most 250 bytes in v1; we send them
  broadcast, so there is no link-layer retransmission and every station in range hears
  every frame.
- **Energy-exhaustion (sleep-deprivation) attacks.** [CITE S4: Stajano's battery
  exhaustion / sleep deprivation, IoT battery DoS surveys.]
- **Client puzzles and cookies.** [CITE S4. Why a stateless cookie only stops off-path
  spoofers on a broadcast medium.]

## 3. Threat model

**Setting.** One battery-powered field node (the responder, *field-1*) and one mains-powered
gateway (the initiator) share a broadcast ESP-NOW channel. Only the gateway initiates
handshakes; a real field node never sends a HELLO (`paper/decisions.md`, Phase 6 #4).

**Attacker capabilities.** The attacker:
- is within radio range and can transmit arbitrary frames at a rate it chooses;
- holds no long-term keys of the legitimate parties;
- can spoof any sender id, including the gateway's, since ESP-NOW frames are not
  authenticated below our protocol;
- hears every frame on the channel, so it can replay captured HELLOs and echo any cookie
  the field node broadcasts;
- knows the defence, its features, thresholds and budget parameters (Kerckhoffs).

We evaluate four attacker behaviours (`paper/decisions.md`, Phase 6 #7, extended by task S5):
- **FLOOD:** forged HELLOs claiming the gateway's id with random signature bytes. ML-DSA
  verification rejects a malformed signature during unpacking, *before* the costly step
  (measured on the rig at about 1.7 ms; `paper/CONTEXT_2026-10-24.md` "Finding 2"), so an
  admitted FLOOD HELLO costs the victim little beyond receiving its 20 frames — it is cheap to
  reject, not cheap to admit and expensive to check.
- **FORGE:** one *structurally valid* ML-DSA-65 signature, produced once by the attacker's own
  enrolled key, then resent unchanged under the gateway's claimed id with a fresh (epoch, seq)
  each time (`firmware/src/attacker/main.cpp`, `MODE FORGE`). Because the signature is correctly
  encoded, it passes the cheap unpacking check FLOOD fails, so field-1 runs the *full*
  verification (Table 4: 26.2 ms, 3.23 mJ above idle) and only fails at the last step, where the
  key and transcript do not match. One signing operation on the attacker forces a full check on
  every resend — this is the asymmetry claim C2 needs, and FLOOD alone does not demonstrate it.
- **INSIDER:** HELLOs validly signed with an *enrolled* attacker key, modelling a compromised
  or hostile enrolled peer. Each admitted HELLO costs verification, encapsulation, a signature
  and a 19-frame RESPONSE.
- **SLOW_DRIP:** INSIDER at about one HELLO per minute, below any fixed rate limit.
- **ADAPTIVE / ADAPTIVE_SPOOF** (Section 8): knows EnergyGate's eight features. Keeps `hs_fail`
  and `dup_pct` at 0 (valid signatures or fresh sequence numbers) and paces `hs_per_s` to stay
  under the score threshold, backing off on a heard CHALLENGE (`firmware/src/attacker/attacker_pacer.h`).

A sender with no enrolled key is dropped by an allow-list check before the gate is consulted,
at negligible cost. EnergyGate matters for spoofed-identity and enrolled-but-hostile senders.

**Out of scope.** Jamming (continuous, detectable, and it does not make the victim spend
energy on cryptography); physical capture and key extraction; side channels (power, timing,
electromagnetic); attacks on the gateway's mains supply; breaking ML-KEM or ML-DSA.

**Goal.** The attacker wins by maximising victim joules spent per attacker joule, or by
denying the legitimate gateway a session. We report both: energy ratio and per-attempt
legitimate handshake success.

## 4. System: the post-quantum handshake

Implementation: `firmware/lib/sentinel_pqc` on PQClean's clean C implementations
(commit `0586a824`, vendored 2026-10-08).

**Protocol.** A signed-KEM exchange in three messages (`pqc_handshake.h`):

```
I -> R  HELLO     cookie(8) | nonce_i(16) | kem_pk | sig_I
R -> I  RESPONSE  nonce_i(16) | nonce_r(16) | kem_ct | sig_R
I -> R  CONFIRM   nonce_r(16) | tag(32)

th1  = XOF("SMv1/th1", I_id, R_id, nonce_i, kem_pk)      sig_I over "SMv1/hello" || th1
th2  = XOF("SMv1/th2", th1, nonce_r, kem_ct)              sig_R over "SMv1/resp" || th2 || R_id || I_id
keys = XOF(96, "SMv1/keys", ss, th2) = k_i2r | k_r2i | k_confirm
tag  = XOF(32, "SMv1/confirm", k_confirm, th2)
```

The XOF is SHAKE256. Authentication uses static, provisioned ML-DSA keys and key agreement
an ephemeral ML-KEM key. Session keys drive AES-256-GCM with the packet header as associated
data. The cookie is deliberately outside the signed transcript: after a CHALLENGE the
initiator resends the same signed HELLO with the cookie filled in, so it does not sign twice.
The protocol is a plain signed-KEM exchange with transcript binding and key confirmation. It
is **not formally verified**; it was host-tested against the real PQClean code for honest runs,
forged signatures, wrong keys, tampered fields, wrong identity, tampered RESPONSE/CONFIRM,
replayed CONFIRM and fragmentation round trips (`firmware/tools/run_pqc_tests.sh`).

**Parameter sets.** Fixed at compile time by NIST level: level 1 = ML-KEM-512 + ML-DSA-44,
level 3 = ML-KEM-768 + ML-DSA-65 (the default). Level 5 is not offered: ML-DSA-87 signing
does not fit: the largest free heap block (110 580 B) allows at most a 94 196 B stack (
`paper/data/E1/README.md`).

**Table 1. Message sizes and ESP-NOW frames** (235-byte payload per frame after a 15-byte
header; `paper/decisions.md` Phase 6 #3).

| Level | HELLO | RESPONSE | CONFIRM |
|---|---|---|---|
| 1 (ML-KEM-512 + ML-DSA-44) | 3244 B, 14 frames | 3220 B, 14 frames | 48 B, 1 frame |
| 3 (ML-KEM-768 + ML-DSA-65) | 4517 B, 20 frames | 4429 B, 19 frames | 48 B, 1 frame |

Because frames are broadcast without link-layer retransmission, a level-3 handshake needs all
39 HELLO and RESPONSE frames to arrive; a lost frame costs a retry.

**Fragmentation and resource bounds.** Messages are split into fragments sharing one
(sender, epoch, seq); the reassembler tracks at most 8 streams with a 3 s inactivity timeout,
so a flood of bogus first fragments cannot exhaust RAM (`sentinel_proto/fragment.h`). All
post-quantum work runs in one dedicated task with a reserved stack (90 112 B at level 3,
49 152 B at level 1); while it is busy, further admissions are refused and counted as
`busy_drop` (`paper/decisions.md` Phase 6 #8). This caps the victim's crypto rate and
means a flood can delay the real gateway even when it costs little energy.

**Replay guard.** Per sender, a ring of the last 8 verified epochs, each with its highest
verified sequence number. Unverified HELLOs never advance it, so a flood with large sequence
numbers cannot lock the real gateway out (`paper/decisions.md` #9, revised by #15).

## 5. EnergyGate

**Where it sits.** On field-1, the node whose battery is at risk, not on the gateway. The
check order for an inbound HELLO is header sanity, replay and freshness, allow-list,
EnergyGate with the joule budget, then reassembly and ML-DSA verification. EnergyGate
decides on the *first fragment*, before reassembly and before any public-key work
(`paper/decisions.md` Phase 6 #6). DROP is silence: the remaining fragments of that set are
ignored. The radio still receives them and the CPU still wakes for each frame; that residual
cost is measured (Section 7), not assumed away.

**Score.** A depth-4 decision tree (`ml/sentinel_ml/energygate.py`, exported to C) maps eight
link features over a rolling 5 s window (five 1 s buckets) to a probability that the sender is
real. Feature order, shared by firmware and training code:
`hs_per_s, hs_fail, rssi_mean, rssi_var, loss_pct, dup_pct, frag_complete_pct, battery_pct`.
Definitions as built are in `paper/decisions.md` Phase 6 #10; in particular `hs_per_s` counts
HELLO attempts, not fragments, and RSSI comes from a promiscuous-mode sniffer keyed on source
MAC because the ESP-NOW receive callback carries none.

**Joule budget.** A token bucket of capacity *B* joules refilling at *r* J/s. An admitted
handshake is charged *c_h*, a challenge *c_c*. The firmware's values (`firmware/src/field_node/main.cpp`,
`sentinel_proto/gate_policy.h`) are still **PLACEHOLDERS**: *B* = 20 J, *r* = 0.05 J/s,
*c_h* = 0.02 J, *c_c* = 0.0005 J. The rig has now measured what they should be:

- field-1's own share of a real handshake's crypto (ML-DSA-65 verify + ML-KEM-768 encaps +
  ML-DSA-65 sign, Table 4) costs **3.23 + 1.10 + 10.6 ≈ 14.9 mJ**; both sides of the handshake
  together (two signs, two verifies, one keygen, one encaps, one decaps) cost about **31 mJ**.
  So *c_h* = 0.02 J (20 mJ) overcharges field-1's own share by about 1.3x, not the "roughly
  right" we first reported — a smaller gap than the FORGE case below, but still an overcharge,
  not a match. With radio and reception the per-handshake cost measured on the mesh ranges
  9-65 mJ (the whole handshake took 80-560 ms; Section 7), so the placeholder sits inside that
  range without being its mean.
- a FORGE HELLO, which never completes a handshake but does run a full ML-DSA-65 verify before
  failing, costs about 3-3.9 mJ: the marked-op estimate from the original rig run was
  3.45-3.9 mJ (Section 8), and the cookie-fix rerun's own FORGE-without-echo reference
  (`paper/data/E_cookie_fix/`: +14.7 ± 0.9 mW at 4.97 verifies/s) agrees at about 3 mJ per
  verify. This is the cost *c_h* is actually charged against when GATE admits a forged HELLO
  under CHALLENGE's rule 2, and the placeholder overcharges that case by about 7x (20 mJ
  against ≈3 mJ; it was sized for a full handshake, not a failed verify).
- *c_c*, the cost of sending one CHALLENGE frame, is **below this rig's resolution** as a
  positive measurement, but we can bound it: every gate-v2 cell whose attacker does not echo a
  cookie (so CHALLENGE dominates, not SPEND) reads within about ±2 mW of zero extra power over
  the 120 s window (Section 8, Table 6). At roughly 600 challenges issued per window
  (`paper/CONTEXT_2026-10-24.md`'s FORGE counts), that bounds *c_c* at about
  2 mW × 120 s / 600 ≈ **0.4 mJ per challenge** — an upper limit from the noise floor, not a
  measured value.

These measured values are not yet written back into the firmware (that is a team decision, not
done for the paper); the PLACEHOLDERs above are what every run in this paper actually used. When
an admission is refused because the crypto task is busy, its charge is refunded.

**The cap only binds in Section 8 because *c_h* is the placeholder, not an honest cost — and
that needs saying plainly, not discovering by rerun.** The budget's sustainable admission rate
is *r*/*c_h*. At the shipped placeholder, that is 0.05 J/s / 0.02 J = 2.5 admits/s, below the
≈4.7-5/s a FORGE attacker sustains, so the bucket drains (Section 8). At the honest cost
measured above (≈3 mJ per forced verify), the same arithmetic gives 0.05/0.003 ≈ **16.7
admits/s** — comfortably above a 5/s attacker's own rate, so on average it would never empty
the bucket at all: this follows directly from the budget's mechanics (Section 5's inequality)
and the already-measured attacker rate and refill rate, and needs no new experiment to show.
**We are not claiming the bound binds against this attacker in general — only that it binds
*here*, because the placeholder happens to overcharge by about 7x.** Setting *c_h* honestly
and *r* from an actual target battery life (not quoted here; it is a team decision, not a
measurement) is future work, and would change which attack rates the budget actually stops.

**Decision rules, policy v2** (default; `gate_policy.h`). With score *p*, spend threshold
0.7 and challenge threshold 0.4 (placeholders):
1. *p* ≥ 0.7 and the budget covers *c_h* → SPEND.
2. A valid cookie came back and the budget covers *c_h* → SPEND, whatever the score.
3. The budget cannot cover one handshake → DROP.
4. *p* ≥ 0.4 → CHALLENGE.
5. Otherwise → CHALLENGE, charged *c_c*; DROP only if even *c_c* cannot be paid.

**Policy v1** (ablation, `-DSENTINEL_GATE_V1`) drops at rule 5 and requires *p* ≥ 0.4 at
rule 2. We keep it because it fails instructively: under flood, forged and real HELLOs claim
the same sender id and the window features cannot tell them apart, so v1 dropped all 10
legitimate handshakes along with 589 forged ones (`paper/decisions.md` #17,
`paper/data/E_phase6/bench_gateway_2026-10-14_flood_defence_gate_full.log`). v2 lets the
real gateway through by echoing the cookie.

**Baselines.** NONE (every HELLO is processed), RATELIMIT (at most one admission per sender
per 10 s, which a one-per-minute slow drip passes by design) and COOKIE (challenge every
sender until it echoes a cookie; no model, no budget).

**What the cookie does not do.** On a broadcast channel an attacker hears every CHALLENGE
and can echo the cookie (`ECHO on` on our attacker). The cookie only stops blind spoofers.
Against a listening attacker the joule budget is what bounds the damage (Section 8).

## 6. Measurement setup

### 6.1 Boards and firmware

Four ESP32-WROOM-32 devkits (ESP32-D0WD-V3, 240 MHz, CP2102 USB bridge): F (field-1, the
victim), G (gateway), A (attacker), M (monitor). Toolchain: PlatformIO 6.2.0, espressif32
7.1.3, Arduino-ESP32 core 4.20017.260907; all 17 firmware environments build
(`paper/setup.md`, Versions). Energy builds strip the demo peripherals (LCD, LEDs, buzzer)
with `-DSENTINEL_MEASUREMENT_BUILD`; there is no battery (`-DSENTINEL_NO_BATTERY` fixes
`battery_pct` at 100, SIMULATED).

**Table 2. Primitive timings, radio off, final** (E1; `paper/data/E1/summary_pooled.csv`;
4 boards, 5 independent sessions each, *n* = 29-30 per board per op, 0 failures). Deterministic
ops are the median of the four boards' medians and agree across boards to within 0.6 % and
with the single-session pilot to 0.1 ms. ML-DSA signing is rejection-sampled, so per-board
medians still move between sessions; its rows report the pooled distribution across all four
boards (*n* = 116) instead of a single median. Classical rows use mbed TLS generic C, not
optimised Curve25519 code, so they are not a fair PQC-versus-classical comparison.

| Algorithm | keygen | encaps / sign | decaps / verify |
|---|---|---|---|
| ML-KEM-512 | 5.93 | 6.05 | 7.35 |
| ML-KEM-768 | 8.60 | 9.88 | 11.61 |
| ML-KEM-1024 | 13.15 | 14.38 | 16.46 |
| ML-DSA-44 | 15.40 | 48.8 median (p10 24.1, p90 92.4, max 166.6) | 15.96 |
| ML-DSA-65 | 26.00 | 63.4 median (p10 37.1, p90 152.7, max 394.8) | 26.25 |
| X25519 | 397.30 | 404.59 (shared secret) | - |
| ECDSA-P256 | 191.15 | 89.07 | 202.43 |

With Wi-Fi running, level-3 signing on the bench took 38-250 ms (median 78) in one earlier
scripted run and 38-287 ms across several runs (`paper/data/E_phase6/README.md`); both are
narrower than E1's radio-off tail (max 394.8 ms, *n* = 116) because they are smaller samples;
rejection sampling has no fixed maximum, so 394.8 ms is the largest value *observed* over E1's
116 signatures, not a proven worst case — report it as E1's wider, better-sampled tail, and the
bench figures only as what a specific scripted run saw. A whole handshake on the bench took
329-545 ms
(median 439, 9 of 9 successful; USB-powered, not an energy measurement).

### 6.2 Energy rig

The victim F is powered only through the sensor, never from USB at the same time (that would
back-feed and bypass the shunt):

```
5 V adaptor (+) -> INA219 VIN+ ; INA219 VIN- -> F VIN
5 V adaptor (-) -> F GND, M GND, INA219 GND
INA219 SDA/SCL -> M GPIO21/22, VCC -> M 3V3
F GPIO4 --1 kohm--> M GPIO4   (operation marker)
```

- **Supply:** a 5 V 2 A wall adaptor, +5.16 V at no load (DT830D), standing in for a battery.
- **Sensor:** INA219 on the high side with its 0.1 Ω shunt, configured for 32 V / 2 A
  (0.1 mA per bit); M reads it at about 989 samples/s over I2C at 400 kHz.
- **Outputs** (`firmware/src/monitor/main.cpp`): every second, the mean current, bus voltage
  and power; for every interval during which F holds GPIO4 high, its duration, energy and peak
  current. The benchmark firmware raises the marker around each primitive; the field-node
  firmware raises it around one whole handshake computation.
- **F's log during energy runs** is read through a separate USB-serial adapter on TX/RX/GND
  (no 5 V), or from G, which relays F's counters over the mesh.

### 6.3 Calibration

Reference current I = V/R from a DT830D multimeter: V across the load while running, R with
the sensor disconnected and test-lead resistance (0.6 Ω) subtracted. Loads are parallel ¼ W
resistors, each at most 0.10 W. Sensor value = 20 s mean of M's per-second readings
(`paper/setup.md`, session 2, 2026-10-24; raw data `paper/data/calibration.csv` and
`calibration_raw_20261024_*.log`; fit `paper/analysis/calibration_fit.py`).

**Table 3. INA219 calibration, session 2.**

| Load | Reference | INA219 raw | Corrected | Residual |
|---|---|---|---|---|
| zero (5 V, no load) | 0 | −0.203 mA | 0.217 mA | – |
| 1 × 1 kΩ | 5.216 mA | 5.160 mA | 5.390 mA | +3.33 % (+0.17 mA) |
| 1 × 270 Ω | 19.292 mA | 19.744 mA | 19.457 mA | +0.85 % |
| 3 × 270 Ω | 57.697 mA | 59.144 mA | 57.460 mA | −0.41 % |
| 5 × 270 Ω | 94.877 mA | 97.398 mA | 94.358 mA | −0.55 % |
| 10 × 270 Ω | 182.642 mA | 188.671 mA | 182.396 mA | −0.13 % |
| 13 × 270 Ω | 232.353 mA | 240.926 mA | 232.799 mA | +0.19 % |

Least squares over the seven points gives I_INA219 = 1.0367 · I_ref − 0.428 mA. Every result
in this paper applies I = (I_raw + 0.428 mA) / 1.0367 in analysis (`paper/analysis/energy.py`);
raw logs stay uncorrected. Because the offset is a current, energy is corrected as
E = (E_raw + 0.428 mA · V · t) / 1.0367.

**Uncertainty.** After correction, residuals are within 0.6 % over 57-232 mA (the ESP32's
working range) and about 0.17 mA below 20 mA; we use max(0.2 mA, 0.6 %) as the random bound and
add one sample period (~1 ms) of timing to each marked interval. Two systematic terms are
quoted separately because they have the same sign for every reading:
- the INA219 reads 3.67 % above the DT830D, and we have not established which instrument is
  right [TODO H: check two loads against a calibrated bench meter]; this affects absolute
  joules (C1) but cancels in energy ratios (C2);
- the INA219 bus voltage reads 1.4 % (5 mA) to 3.1 % (232 mA) above the DT830D; the growing part
  is a real ~0.3 Ω drop in the jumper and breadboard between sensor and load. Bus voltage is
  not corrected.

A trial calibration session (2026-10-21) is excluded: a failing test lead inflated low
resistances and two readings had an unseated jumper.

## 7. Results: cost of the handshake (C1)

**Table 4. Energy per crypto operation**, radio off, measured on the rig (`paper/data/E2/`,
2026-10-26: F running `benchmark_energy`, 240 MHz, PQClean clean C, powered only through the
calibrated INA219; `BENCH_REPEAT` = 20, marker around every op, 20 ms gap). Idle with the radio
off is 225 mW; "above idle" subtracts idle power × op duration. Mean over *n* = 20.

| Operation | Time (ms) | Total mJ | Above idle mJ |
|---|---|---|---|
| ML-KEM-512 keygen / encaps / decaps | 5.9 / 6.1 / 7.4 | 1.94 / 2.06 / 2.52 | 0.62 / 0.68 / 0.85 |
| ML-KEM-768 keygen / encaps / decaps | 8.6 / 9.7 / 11.5 | 2.91 / 3.27 / 3.93 | 0.98 / 1.10 / 1.34 |
| ML-KEM-1024 keygen / encaps / decaps | 12.8 / 13.9 / 16.6 | 4.41 / 4.76 / 5.69 | 1.53 / 1.63 / 1.97 |
| ML-DSA-44 keygen / sign / verify | 15.4 / 44 / 16.2 | 5.30 / 15.4 / 5.57 | 1.83 / 5.4 ± 1.3 / 1.93 |
| ML-DSA-65 keygen / sign / verify | 26.0 / 86 / 26.2 | 9.05 / 30.0 / 9.14 | 3.19 / 10.6 ± 4.1 / 3.23 |
| X25519 keygen / shared secret | 458 / 476 | 145 / 150 | 42.2 / 43.3 |
| ECDSA-P256 keygen / sign / verify | 251 / 115 / 265 | 78 / 36 / 82 | 21.4 / 9.9 / 22.7 |

Peak current during crypto is about 71 mA (radio off). ML-DSA-65 sign has the widest spread
(±4.1 mJ, matching the 38-287 ms signing-time variance from rejection sampling).

At level 3, field-1's own share of one handshake's crypto is ML-DSA-65 verify (HELLO's
signature) + ML-KEM-768 encaps (the shared secret) + ML-DSA-65 sign (RESPONSE's signature):
**3.23 + 1.10 + 10.6 ≈ 14.9 mJ above idle**. Both sides of the handshake together — one ML-KEM-768
keygen, encaps and decaps, and two ML-DSA-65 signs and verifies — cost
0.98 + 1.10 + 1.34 + 2×10.6 + 2×3.23 ≈ **31 mJ**. The budget's placeholder *c_h* = 20 mJ
(Section 5) is about 1.3x field-1's own 14.9 mJ share, an overcharge but a much smaller one than
the ~5x it overcharges a failed FORGE verify (Section 8). The classical baselines (X25519,
ECDSA-P256) use mbed TLS generic C, not optimised implementations — do not read them as PQC
beating classical.

**Table 5. Handshake and forgery energy on the real mesh, radio on** (`paper/CONTEXT_2026-10-24.md`;
F idles at about 598 mW with the radio always on, dominating any attack's extra draw — stating
this duty-cycle assumption is required before any claim generalises to a sleeping node):

| Event | Energy above idle | Source |
|---|---|---|
| One legitimate handshake | 9-65 mJ (80-560 ms end to end; ML-DSA signing within it varies most) | E_rig, n=1 per condition |
| One admitted FORGE HELLO (full verify, fails at the end) | ≈3.45 mJ per marked op (original rig run), ≈3 mJ from a dedicated no-echo reference rerun | E5 rig (Section 8); E_cookie_fix |
| One admitted FLOOD HELLO (rejected during signature unpacking) | not measurably different from zero (Section 8) | E5 rig |

[Figure 1: current trace of one handshake with phases marked — not yet made.]

## 8. Results: the attack and the defences (C2, C3)

**Table 6. E5 energy grid.** Each cell attacks for 120 s at 5 HELLO/s (SLOW_DRIP instead sends
about 1 HELLO/min); "extra F power" is field-1's mean power during that 120 s window minus its
mean power in the minute immediately before the attack started. *n* = 5 reps per cell, 95 % CI
(`paper/data/E5_rig/`, 2026-10-25/27, corrected to the 1 s mean `power_mw`, not the aliased
instantaneous `amps` sample — see the method note below). Legit success is the real gateway's
handshakes ok/started during the attack window.

| Defence | Attack | Extra F power | Legit success |
|---|---|---|---|
| none | FLOOD | +1.8 ± 2.2 mW | 0.71 ± 0.23 |
| none | **INSIDER** | **+91.2 ± 3.3 mW (+15.2 %)** | 0.21 ± 0.15 |
| none | SLOW_DRIP | +0.2 ± 0.6 mW | 0.96 ± 0.11 |
| none | **FORGE** | **+19.0 ± 1.4 mW (+3.2 %)** | 0.28 ± 0.24 |
| none | **ADAPTIVE** | **+28.9 ± 2.3 mW** | 0.30 ± 0.30 |
| none | ADAPTIVE_SPOOF | -0.4 ± 1.8 mW | 0.65 ± 0.64 |
| ratelimit | FLOOD / INSIDER / SLOW_DRIP | -2.2 / -1.4 / +0.4 mW | **0.00** / 0.87 / 0.81 |
| cookie | FLOOD / INSIDER / SLOW_DRIP | +1.8 / +1.4 / -0.1 mW | 0.79 / 0.77 / 1.00 |
| cookie | FORGE / ADAPTIVE / ADAPTIVE_SPOOF | +0.8 / +1.2 / -1.4 mW | 0.24 / 0.53 / 0.52 |
| gate v2 | FLOOD / INSIDER / SLOW_DRIP | +1.7 / +1.1 / +0.7 mW | 0.75 / 0.82 / 1.00 |
| gate v2 | FORGE / ADAPTIVE_SPOOF | +1.4 / -0.4 mW | 0.23 / 0.47 |
| gate v2 | **ADAPTIVE** | **+25.5 ± 3.0 mW** | 0.45 ± 0.33 |
| gate v1 (ablation) | FLOOD / INSIDER | -2.6 / -3.0 mW | **0.04 / 0.02** |

F idles at about 598 mW with the radio always on. Legit-success intervals are wide (a few
handshakes per 120 s window); a longer attack window would tighten them.

**Method note.** M's `NRG` line carries `power_mw` (a true 1 s mean) and `amps` (one
instantaneous sample). An earlier pass used `amps`; at an attack paced to an exact 5 Hz against
M's exact 1 Hz report, that sample aliases to the same phase of F's busy cycle every second (one
early FORGE run read as low as ~0 mW, another +125 mW, from the same condition). All numbers
above use the corrected `power_mw`; marked-op energies (`monitor,op_N`) were never affected.
**`paper/analysis/energy.py` already reads `power_mw`, not `amps`, for exactly this reason**
(see its docstring). Anyone extending the analysis should keep doing the same.

**What this shows, honestly:**
- **FORGE is the cheap-attacker/costly-victim attack** FLOOD is not: each admitted HELLO forces
  a full ML-DSA-65 verify (Table 4) that only fails at the end, at ≈3.45-3.9 mJ per HELLO, while
  the attacker signs once per run. FLOOD costs nothing measurable, confirming Section 3's claim
  that random signatures are rejected cheaply.
- **INSIDER remains the largest undefended drain** (+15.2 %) and starves the real gateway (21 %
  success); every defence removes the drain, but RATELIMIT does it by locking out the real
  gateway too (0 % under FLOOD) — a denial of a different kind.
- **COOKIE and GATE v2 look alike here** because none of these attackers echoes a cookie yet;
  FORGE+ECHO (below) is what separates them.
- **GATE v1 (the ablation) locks out the real gateway** (2-4 % success) exactly as the design
  decision for v2 predicted (`paper/decisions.md` #17): forged and real HELLOs look alike to the
  window features, so dropping low scores outright drops both.
- **Rate sweep** (*n* = 3, 5/20/50 HELLO/s): INSIDER's drain is flat (+94 to +96 mW) at every
  rate without a defence — F's single crypto slot is already saturated at 5/s, so a faster
  INSIDER is busy-dropped, not admitted more often; with the gate it drops to about +1.5 mW at
  every rate. FLOOD's drain stays near zero at every rate, but legitimate success falls from
  about 0.5 at 5/s to about 0.07 at 20 and 50/s, with or without the gate: a fast FLOOD denies
  connectivity through airtime and reassembly contention, not energy — a distinct failure mode
  from the one this paper's energy claim is about.
- **30-minute SLOW_DRIP** (*n* = 2) shows no measurable extra power either way.

**FORGE + ECHO, original run** (`paper/CONTEXT_2026-10-24.md`, 2026-10-27, 10 runs, gate-v2
firmware 76692eb): the attacker echoed the cookie FORGE's resent HELLO received back, patched it
into the cached template, and reused it unchanged — +15.1 ± 2.4 mW under COOKIE, +16.0 ± 0.5 mW
under GATE v2 (both *n* = 5), legit success ≈0.13-0.14. The cookie as built then was *reusable*:
it was not bound to a HELLO's nonce or (epoch, seq), so one echoed cookie admitted every later
resend of the same cached template regardless of its (epoch, seq), and GATE v2's rule 2 ("a
returned cookie admits whatever the score") let the same HELLOs through on top of that. This was
a genuine weakness, and we reported it as one rather than a result to be proud of.

**The cookie has since been bound to (sender, epoch, seq, time window)**
(`firmware/lib/sentinel_proto/cookie.{h,cpp}`), closing the *reuse*: a resend with a different
(epoch, seq) now needs its own CHALLENGE round trip. The first version of this fix broke the
*real* gateway — its own cookie retry also sent a fresh (epoch, seq), so a bound cookie never
verified for it either, locking it out under COOKIE and whenever GATE's score was low — caught
in review before any rig time was spent on it, and fixed by having the gateway keep the
challenged (epoch, seq) on a retry (`firmware/src/gateway/main.cpp`), matching what
`paper/decisions.md` #5 already specified for a legitimate initiator.

**Table 6b. Cookie-fix rerun** (`paper/data/E_cookie_fix/`, 2026-10-30/31, INA219 rig, firmware
`7afdea4`, 53 runs; 900 s windows used throughout except where marked, since early 120 s runs
fall in a noisier stretch of the session — see that README's Limits). The attacker now has
`ECHO same`, which answers a CHALLENGE under the *same* (epoch, seq) it was issued for — the
behaviour a real echoing attacker needs, and the one `ECHO on`'s old fresh-seq echo never was.

| Defence | Attacker | Window | Extra F power | Admits/s | Real gateway |
|---|---|---|---|---|---|
| none | none (control) | 900 s | +0.2 ± 0.4 mW | – | 128/132 overall, no attack |
| none | FORGE, no echo | 120 s | +14.7 ± 0.9 mW | 4.97 | 17/35 |
| cookie | FORGE, no echo / old (fresh-seq) echo | 120 s | within ≈1 mW of idle | ≈0.05 | 11/19, 6/47 |
| gate v2 | FORGE, no echo / old (fresh-seq) echo | 120 s | within ≈1 mW of idle | ≈0.07 | 11/26, 4/51 |
| cookie | `ECHO same` | 900 s | **+13.0 ± 1.0 mW** | 4.71 | 41/198 (21 %) |
| gate v2 | `ECHO same` | 900 s | **+12.2 ± 4.3 mW before the bucket empties → +5.5 ± 2.4 mW after** | 4.50 → 2.42 | 13/172 (8 %) |

**The fixed cookie makes `ECHO same` dearer for the attacker, it does not close the attack —
say exactly that, not "fixed".** A non-echoing or old fresh-seq-echo attacker is now stopped
(within about 1 mW of idle, against the undefended reference of about +14.7 mW); a same-seq
echo still drains +13.0 mW under COOKIE, about 12 % below the undefended figure. The fix moved
the attacker's cost from about 30 cheap echoes per run (the old, reusable cookie) to one echo
per admitted HELLO — roughly 4.6-4.7 echoes/s, about double the frames on the air — but COOKIE
itself has no energy budget, so that extra cost does not translate into less drain at the victim.

**Under GATE v2, the joule budget is what actually limits a same-seq echo, and this is now a
direct, measured result, not an estimate.** Three 900 s `ECHO same` runs against GATE v2 each
ran the bucket dry (+633 s, +412 s, +415 s from varying starting balances) and admissions then
settled at 2.42 admits/s, matching the *r*/*c_h* = 2.5/s bound; extra power fell from
**+12.2 ± 4.3 mW before the bucket emptied to +5.5 ± 2.4 mW after** — this measured figure
**replaces** the 8.6 mW ESTIMATE from the earlier counters-only budget run (below), while COOKIE
(no budget) stays flat at +13.0 mW for as long as the attack runs. The first several minutes of
any GATE v2 run show no benefit over COOKIE at all; the gap only opens once the bucket empties.

**Availability is a separate finding this rerun surfaces, and the paper needs to say it
plainly: these defences protect energy, not availability.** The real gateway's success rate
tracks the attacker's *frame rate*, not whether field-1 is verifying anything: 49 % success at
100 forged frames/s whether field-1 checks every forged HELLO (no defence) or none at all
(COOKIE/GATE with no echo), and 8-21 % once the attacker echoes (more frames per admitted
attempt). The mechanism is consistent with frame loss or airtime contention — a handshake needs
all 39 HELLO+RESPONSE frames to arrive — but no frame-level loss was measured directly, so this
is an observation, not a measured cause. Neither COOKIE nor GATE v2 restores availability in
these runs; both recover within the last minute once the attack stops.

An earlier INSIDER-ECHO block (10 runs) is **excluded** (`runlog.csv`, `excluded=y`): the
attacker's cookie echo only fires when its crypto task is idle and the challenge matches its
latest HELLO, and at 5/s INSIDER is always signing, so it heard thousands of CHALLENGEs but sent
zero echoes. The bug is in the attacker, not the defence; it does not affect any other row.

**Still to do for this section (claim C2 is not yet stated as a ratio):** the attacker's own
energy per run is still ESTIMATED from airtime, not measured — a second INA219 monitor would
measure it directly (team decision E3, Section 10). Without it we can report victim joules but
not victim-joules-per-attacker-joule, which is what C2 actually claims; that ratio, and a figure
of it per defence × attack cell, is still outstanding. Also still to make: Figure 1 (a current
trace of one handshake with phases marked, Section 7) and Figure 2 (victim power over time for
each defence under FLOOD, referenced in the original task list for this section).

**Budget bound under an adaptive attacker.** We built an ADAPTIVE attacker
(`firmware/src/attacker/main.cpp`, `attacker_pacer.h`) that knows EnergyGate's 8 features: it
signs every HELLO with its own enrolled key (`hs_fail` stays 0) and sends a fresh sequence
number each time (`dup_pct` stays 0), so of the three features it can move, only `hs_per_s` is
left, and it paces that to stay just under the shipped tree's split (Section 5). ADAPTIVE_SPOOF
is the same pacing with forged, unsigned HELLOs instead. Both back off multiplicatively on a
heard CHALLENGE and probe back up additively (AIMD), tracked against field-1's own 5-bucket
window so the pacer reflects what the gate will actually see, not a fixed guess.

The bound itself does not depend on fooling the classifier correctly: `EnergyBudget`
(`sentinel_proto/energy_budget.h`) never spends more than it holds and refills at a fixed rate
*r*, so for *any* sequence of admitted SPENDs and CHALLENGEs over a window of length *T*,

  total budgeted spend(*T*) ≤ *B* + *r*·*T*,  and so  average budgeted power ≤ *r* as *T* → ∞.

This holds whatever the score says, including a classifier a future attacker fools outright. It
does **not** bound the reception cost of frames field-1 processes before the gate decides; that
part is bounded instead by the attacker's own pacer cap, not by the victim. `paper/analysis/drain_bound.py`
computes both parts and their sum (derivation and formulas in its docstring; tested in
`test_drain_bound.py`). With today's PLACEHOLDER budget (*B* = 20 J, *r* = 0.05 J/s) and an
ESTIMATED per-attempt reception cost, the long-run worst case is about 50 mW budgeted plus
about 1 mW unbudgeted — about 51 mW total.

**The bound has two direct tests now, not one, and the second is the one to cite.** A 120 s
window is too short at the placeholder's capacity (the original FORGE+ECHO run above: ≈540
spends × 0.02 J ≈ 10.8 J against 20 J + 6 J of refill — well under capacity), so we ran it
longer. The first attempt, 3 × 600 s FORGE+ECHO at 5/s against GATE v2 on the *old, reusable*
cookie (boards on USB, no INA219, `paper/data/E_budget/`, 2026-10-27 evening), measured the
budget's own counters rather than power, so it tests the admission-rate mechanism directly
rather than inferring it from watts. The budget ran dry in every run — rep 1 from a full 20 J
bucket at +537 s, close to the ≈500 s a full bucket predicts at this attack's net drain;
reps 2-3 started part-filled at 8.6 J (170 s between attacks in that session only refilled 8.5 J
of a 400 s-to-fill bucket) and emptied at +235 s and +260 s. After emptying, admissions in all
three runs settled at **2.48-2.49 spends/s**, matching *r*/*c_h* = 0.05/0.02 = **2.5/s** almost
exactly; everything else was DROPped by rule 3 — the inequality above holding in practice, not
just in the arithmetic, whatever the attacker does once the bucket is empty.

**The second test, after the cookie fix, replaces that run's energy estimate with a real
measurement.** The `ECHO same` rerun in Section 8 (Table 6b) repeats this exact mechanism on the
*bound* cookie and the *fixed* gateway, this time on the INA219: three 900 s runs, bucket empty
by +412 to +633 s, admissions settling at 2.42 spends/s (again close to the 2.5/s bound), and
measured extra power falling from +12.2 ± 4.3 mW before the bucket empties to
**+5.5 ± 2.4 mW, measured,** after — **this is the number to quote, not the ≈8.6 mW the first
run could only estimate** (it had charged ≈3.45 mJ per admit from Table 5 against no power
reading at all). That is the honest form of claim C3: the budget does bound the admission
*rate* once exhausted, demonstrated twice now; it does not bound the energy per admission,
which is still whatever *c_h* undercharges (Section 5) — and Section 5 also now shows that this
bound would not have engaged against this attacker at all had *c_h* been set honestly, since an
honest *c_h* raises the sustainable rate above the attacker's own.

Against ADAPTIVE, the comparison is weaker evidence than either direct test: under GATE v2 it
measured +25.5 ± 3.0 mW and undefended +28.9 ± 2.3 mW (Table 6), both under the ≈51 mW
drain-bound estimate from `paper/analysis/drain_bound.py` (derivation and formulas in its
docstring; tested in `test_drain_bound.py`), but ADAPTIVE's own 120 s runs never came close to
emptying the bucket either, so those two numbers show the bound was not yet *violated*, not that
it was *exercised* — the FORGE + `ECHO same` runs above are what actually drove the budget to
its floor and are the stronger results.

## 9. EnergyGate on recorded traces

**Data.** Field-1's own 8 features plus the SIMULATED-trained model's live score, printed once a
second by the bench firmware (`FEAT` rows) under GATE v2, labelled from each run's timeline:
6 attacks (FLOOD, INSIDER, SLOW_DRIP, FORGE, ADAPTIVE, ADAPTIVE_SPOOF) × 3 sessions, plus 3
FORGE+ECHO sessions from the budget run (Section 8) — 6 sessions, 6,968 rows after dropping the
few boundary rows neither class describes cleanly (`paper/data/E9_traces/`, 2026-10-27 evening;
boards on USB, no INA219 — this retrain uses no power data). `battery_pct` is dropped: it is a
constant 100 here (no battery on this rig, SIMULATED). `rssi_mean`/`rssi_var` read 0 when no
HELLO arrived in the window, which is missing data, not a real 0 dBm, so we report both with and
without those two features. `paper/analysis/e9_retrain.py` does the retraining and the
comparison below; it is the canonical script for this section's numbers (also what
`paper/ieee/paper.tex` quotes), reading field-1's own FEAT rows, not the console-style traces
`ml/train_energygate.py` still trains the shipped model from.

*A note on method, so a reader comparing scripts is not confused:* an earlier pass through this
data (`ml/train_energygate_real.py`, kept for its extra per-session breakdown and its direct
port of the firmware's own non-trained fallback rule) computed TPR at 1 % FPR by linearly
interpolating between the two nearest ROC points, which can imply an operating point no actual
threshold achieves. `e9_retrain.py` instead reports the best TPR among thresholds that do not
*exceed* 1 % FPR — more conservative, and the number we use throughout this paper (0.751 for
the shipped model, not 0.754).

**Table 7. AUC and TPR at 1 % FPR**, evaluated by leave-one-**session**-out (never a random
split — rows one second apart over a 5 s window overlap). The retrained rows pool every
held-out session's predictions into one ROC curve; the shipped and rate-rule rows are each one
fixed scorer with no retraining, evaluated on every row the same way. Per-label detection rates
are at score threshold 0.5.

| Model | AUC | TPR @ 1 % FPR | SLOW_DRIP | ADAPTIVE | ADAPTIVE_SPOOF | FORGE_ECHO |
|---|---|---|---|---|---|---|
| SIMULATED-trained (shipped today) | 0.876 | 0.751 | 0.00 | 0.00 | 0.00 | 1.00 |
| Rate rule (`hs_per_s` > 0.5) | 0.905 | 0.809 | 0.00 | 0.82 | 0.06 | 1.00 |
| Retrained on real traces, with RSSI | 0.935 | 0.881 | 0.05 | 0.93 | 0.74 | 1.00 |
| **Retrained on real traces, without RSSI** | **0.950** | **0.903** | 0.07 | 0.97 | 0.86 | 1.00 |

Dropping RSSI *improves* both AUC and TPR slightly, so the suspected leak (any RSSI sample at
all correlating with "a HELLO arrived," which correlates with an attack in these particular
sessions) is not inflating the with-RSSI numbers above the without-RSSI ones here; if anything
the two RSSI features add noise on this rig. We still report both, since a different session
mix could tip that the other way, and recommend training without RSSI until a trace set has
attacks that genuinely look different in signal strength. The simple rate rule — a single
threshold on `hs_per_s`, the one feature the shipped tree's own split already leaned on — beats
the shipped model outright and catches most of ADAPTIVE (0.82) that the shipped model missed
entirely (0.00), but it still misses ADAPTIVE_SPOOF (0.06) and SLOW_DRIP (0.00): pacing is
enough to beat a rule that only looks at rate, but not a tree that can also use the other six
features, which is why the retrained tree does better still (0.86 and 0.07 respectively).

**Retraining helps a lot against the one attacker that targeted this exact tree, and not at all
against the one attacker that was never going to be caught by these features.** ADAPTIVE and
ADAPTIVE_SPOOF (`firmware/src/attacker/attacker_pacer.h`) were built to pace `hs_per_s` just
under the *shipped* SIMULATED-trained tree's split (Section 8), so it is unsurprising that
model misses them entirely. Retraining on traces that actually contain ADAPTIVE closes most of
that gap — catching 97 % of it — because the tree can now draw a split the pacer's target model
never had reason to defend against. This is the ordinary arms race: a classifier retrained
against a known attacker catches that attacker. **SLOW_DRIP is different:**
it evades both models almost completely (7 % caught, even retrained), because at about one
HELLO/minute it genuinely does not raise `hs_per_s` or any of the other 7 features inside the
5 s window these features are computed over — there is no split a tree over these features
*could* draw that would catch it without flagging ordinary low-rate traffic too. **This is the
honest version of claim C3, stated carefully:** EnergyGate's score, however well trained, cannot
see SLOW_DRIP. The budget is not what saves field-1 from it either — at one admitted HELLO per
minute, SLOW_DRIP charges only *c_h*/60 s ≈ 0.02 J / 60 s ≈ 0.33 mW against a 50 mW refill rate,
nowhere near enough to ever threaten the bucket (Section 8's budget tests both needed a 5 HELLO/s
attacker to drain it at all). SLOW_DRIP is harmless here simply because its own drain is tiny
(+0.2 mW, Table 6), not because any defence is doing something about it. The honest claim is
narrower than "the budget is the guarantee": the budget is the guarantee against the *fast*
attackers that can actually threaten it (Section 8); against a slow one that the score also
cannot see, nothing in this system is doing anything — it survives only because it costs so
little to let through.

**Limitations specific to this retrain:** one rig, one room, one fixed distance between boards
— a held-out *session* is not a held-out *environment*, and these numbers should not be read as
generalising to a different physical deployment. Under GATE v2 throughout, attacker traffic is
shaped by what the gate allows through (e.g. INSIDER's `hs_fail` stays 0 because it is
challenged, not admitted, so verification never runs and never fails), so these features
describe traffic *as filtered by* the defence being evaluated, not raw attacker behaviour. The
retrained model is not exported to firmware for this paper (`ml/export/energygate.h` is
unchanged); doing so, and rerunning Section 8's grid against it, is future work.

## 10. Limitations

- **No battery.** The victim runs from a 5 V adaptor through the sensor; `battery_pct` is fixed
  at 100 (SIMULATED) and battery-life figures are derived from joules, not measured run-down.
- **The shipped firmware still carries the SIMULATED-trained model.** It was trained on
  simulated traces with slightly different feature definitions from the firmware, and Section 9
  has since retrained on real recorded traces and reported how that compares — but that retrained
  tree is not exported to `firmware/lib/sentinel_proto/energygate_model.h`, so every power and
  availability result in this paper (Section 8) still ran against the original SIMULATED-trained
  model. Deploying the retrained model and rerunning Section 8 against it is future work.
- **Placeholder costs, now measured but not applied — and shown to change which attacks the
  budget stops.** The joule budget's capacity and refill rate are still placeholders. The
  handshake cost placeholder (20 mJ) overcharges field-1's own measured share of a handshake
  (≈14.9 mJ, Table 4) by about 1.3x, and overcharges a failed FORGE verify (≈3 mJ, Section 8)
  by about 7x; the challenge cost is below this rig's resolution as a positive measurement
  (bounded above at ≈0.4 mJ, Section 5). This is not a minor rounding issue: Section 5 shows
  that at the honest ≈3 mJ cost the budget's sustainable rate (*r*/*c_h* ≈ 16.7 admits/s) would
  sit *above* the 5 HELLO/s FORGE attack's own rate, so the bound demonstrated in Section 8 binds
  *only because of the placeholder* — an honestly-costed budget would not have emptied against
  this particular attacker at all. None of this was written back into the firmware for this
  paper — every run here used the original placeholders.
- **Absolute energy depends on an unsettled reference.** The INA219 and the DT830D differ by
  3.67 % in gain and 1.4-3.1 % in voltage; ratios are unaffected.
- **Unauthenticated control channel.** GATE_REPORT, CONTROL and CHALLENGE travel in plaintext
  on the same radio the attacker shares; this is a lab rig.
- **The cookie was not just echoable but reusable — fixed, and the fix rerun.** It used to be
  bound to neither the HELLO's nonce nor its (epoch, seq), so a single echoed cookie admitted
  every later resend of the same cached template (Section 8): the attacker echoed about 30
  cookies per 120 s run but that admitted roughly 540 forged HELLOs. `firmware/lib/sentinel_proto/cookie.{h,cpp}`
  now binds the cookie to (sender, epoch, seq, time window); a legitimate retry resends the
  exact header it was challenged on (`firmware/src/gateway/main.cpp`, matching
  `paper/decisions.md` #5) and still verifies, but an attacker that mutates (epoch, seq) on
  every resend now needs one fresh CHALLENGE round trip per admitted HELLO, not per window.
  **The first version of this fix broke the real gateway** — its own cookie retry also used a
  fresh (epoch, seq), so it was locked out too; this was caught in review and fixed before any
  rig time was spent on it. The rig rerun (Section 8, `paper/data/E_cookie_fix/`, 53 runs)
  confirms the real gateway is not locked out (128/132 with no attack) and that the fix **makes
  a same-seq echo dearer for the attacker, it does not close the attack**: COOKIE alone still
  drains +13.0 mW against a +14.7 mW undefended reference (about 12 % less, and with no budget
  to fall back on); GATE v2 does better once its budget empties (+5.5 mW), for the reasons
  above. The rerun also surfaced a result outside this bullet's scope: the real gateway's
  success rate tracks the attacker's frame rate, not its own crypto load — see Section 8's
  availability finding.
- **Our defences protect energy, not availability, and the paper should not blur that.** The
  cookie-fix rerun (Section 8) found the real gateway's success rate tracks the attacker's
  frame rate — 49 % at 100 forged frames/s whether field-1 verifies every one of them or none,
  dropping further once the attacker echoes — not whether field-1 is spending crypto cycles.
  Every defence in this paper is scored on energy and on legitimate success together (Table 6),
  but none of them was designed to, or shown to, restore availability under load; that would be
  a different mechanism (frame-level admission or airtime shaping) than anything evaluated here.
- **Insider onset.** The score reacts to the 5 s window, so a few insider HELLOs are admitted
  before the window fills (about 5 of 566 in one bench run).
- **Replay ring.** A captured signed HELLO whose epoch has aged out of the 8-entry ring can be
  replayed once and costs one full handshake.
- **Not formally verified.** The handshake is a plain signed-KEM exchange; we make no
  formal-security claim.
- **Demo keys** compiled into every image are not key management.
- **ML-DSA-87 does not fit** the ESP32 heap, so NIST level 5 is not evaluated.
- **Classical baselines** are generic mbed TLS code, not optimised implementations.
- **One chip type, one victim, one legitimate peer.** No second chip family (ESP32-S3/C6) and no
  additional legitimate nodes. [Team decision pending: E6, E9.]
- **Attacker energy** is ESTIMATED from airtime until a second monitor measures it. [Team
  decision pending: E3.]
- **Link quality confounds.** Intermittent handshake timeouts on weak links (one run at −61 dBm
  had a 4 of 9 no-attack baseline); runs are done with boards adjacent and the baseline reported.
- **Unresolved earlier observation.** A partial log showed 0 of 7 legitimate handshakes under an
  undefended flood that a scripted rerun did not reproduce (9 of 9); it is not cited as a result.
- **Signing-time variance** with Wi-Fi on (38-287 ms across runs) makes per-handshake latency
  heavy-tailed; we report median and tail.

## 11. Related work

*(Ported from `paper/ieee/paper.tex`, the canonical source; its reference list has the full
citations. The systematic literature pass this condenses is `paper/writing/related_work.md`.)*

**ML-KEM and ML-DSA.** ML-KEM is a module-lattice KEM and ML-DSA a module-lattice signature with
rejection-sampled signing, so its signing time is variable [FIPS 203; FIPS 204]. We use
PQClean's portable C implementations.

**ESP-NOW** is Espressif's connectionless vendor-frame protocol, at most 250 bytes per frame in
v1. We broadcast, so there is no link-layer retransmission and every station in range hears
every frame.

**PQC cost on small devices.** Gillot et al. measure ML-KEM/ML-DSA/SLH-DSA energy on Raspberry
Pi and laptop platforms and TLS 1.3 PQC handshakes on Pico W, ESP32 and Pi Zero; Karcz et al.
time the NIST schemes on an ESP32-C6. All characterise the cost the device *wants* to pay. None
measures the cost an adversary chooses when to impose.

**Handshake exhaustion.** Lee et al. show PQC-TLS prolongs high server CPU load under handshake
exhaustion by up to 88× and degrades learned IDSs — server CPU, not battery. Hummen et al.
protect constrained peers' public-key work with puzzles; client puzzles and cookies for key
exchange are well studied. On a broadcast medium a stateless cookie only stops blind spoofers
— our own FORGE + ECHO result (Section 8) is a direct demonstration of that limit, and of what
still bounds an attacker once the cookie is beaten.

**Battery exhaustion.** Stajano and Anderson named "sleep deprivation torture"; Pirretti et al.
analyse sleep-deprivation attacks in sensor networks. Those defences sit at the MAC/clustering
layer. From a first, non-systematic search (`paper/writing/related_work.md`) we found no prior
measurement of the battery cost of abusive post-quantum handshake requests on a microcontroller
and no defence that bounds it with a joule budget independent of a classifier; we do not claim
this is exhaustive.

## 12. Conclusion

*(Ported from `paper/ieee/paper.tex`, the canonical source.)*

On a battery-powered post-quantum responder the battery, not the message, is the attack
surface: an enrolled insider raises the victim's power by 15 % and a single forged signature,
resent, forces a full ML-DSA verify every time. A first-fragment gate removes most of the
damage cheaply, but a learned score is evadable, and binding the broadcast cookie to the exact
HELLO it answers makes a real echo dearer rather than free. The joule budget is the part that
does not depend on being right about the attacker or the cookie: on the rig it pinned
admissions to *r*/*c_h* and cut a same-seq echo's drain from +12.2 to +5.5 mW once it ran dry —
but only because our placeholder cost overcharges a forged verify by ≈7×; at an honest cost the
same attacker would never have drained it. Our defences also protect energy, not availability:
the gateway's success tracked the attacker's frame rate regardless of which defence ran. Next
steps are an honestly-costed budget (with *r* set from a target battery life), deploying the
retrained gate, a second monitor for attacker energy, and a duty-cycled victim.

## Artifact

Repository layout for reviewers: `firmware/` (all board firmware, host tests), `ml/` (EnergyGate
training and export), `paper/data/` (raw logs, never edited; `paper/runlog.csv` lists every run,
excluded ones marked), `paper/analysis/` (scripts that rebuild every table), `paper/setup.md`
(rig and calibration record).
