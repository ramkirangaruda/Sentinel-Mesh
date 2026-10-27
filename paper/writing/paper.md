<!--
SentinelMesh paper draft (task S6, paper/WORK_SPLIT.md). Owner: person S.
Markdown for now; convert to the venue's LaTeX template with pandoc once a venue is chosen.
Every number here cites the repo file it comes from. Markers:
  [TODO S2] / [TODO S3] / [TODO S5] / [TODO S7]  filled from that task's tables
  [CITE ...]                                     filled by S4 (paper/writing/related_work.md)
  SIMULATED / ESTIMATED / PLACEHOLDER            stay in the text until real data replaces them
-->

# The Battery, Not the Message: Measuring and Bounding Energy-Exhaustion Attacks on Post-Quantum Handshakes in a Microcontroller Mesh

*Working title. Authors: Navika Kapoor, Chaitanya Patil, Adithya Binoj Nair, Ramkiran (team "One Last Run").*

## Abstract

[TODO after S2/S3. About 200 words, in this order: the problem (a forged post-quantum HELLO
costs a battery-powered node a signature verification, and more if admitted); what we
measured (per-operation and per-handshake energy on an ESP32 with the radio on, through a
calibrated INA219 rig); the attack (victim joules per attacker joule for flood, insider and
slow-drip attackers); the defence (EnergyGate: a first-fragment score and a joule budget
deciding spend, challenge or drop before any public-key work); the headline numbers with
their 95 % CIs; the bound that still holds when the classifier is fooled; the artifact.]

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
  9-65 mJ (ML-DSA signing time varies 80-560 ms; Section 7), so the placeholder sits inside that
  range without being its mean.
- a FORGE HELLO, which never completes a handshake but does run a full ML-DSA-65 verify before
  failing, costs about 3.5-3.9 mJ (Section 8) — this is the cost *c_h* is actually charged
  against when GATE admits a forged HELLO under CHALLENGE's rule 2, and the placeholder
  overcharges that case by about 5x (it was sized for a full handshake, not a failed verify).
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

**Table 2. Primitive timings, radio off** (E1; median of four boards' medians, ms;
`paper/data/E1/summary_pooled.csv`). Classical rows use mbed TLS generic C, not optimised
Curve25519 code, so they are not a fair PQC-versus-classical comparison.

| Algorithm | keygen | encaps / sign | decaps / verify |
|---|---|---|---|
| ML-KEM-512 | 5.93 | 6.05 | 7.35 |
| ML-KEM-768 | 8.59 | 9.88 | 11.60 |
| ML-KEM-1024 | 13.14 | 14.37 | 16.46 |
| ML-DSA-44 | 15.36 | 57.67 (boards 46.2-65.0) | 15.97 |
| ML-DSA-65 | 26.00 | 63.24 (boards 37.1-76.2) | 26.25 |
| X25519 | 397.45 | 403.76 (shared secret) | - |
| ECDSA-P256 | 191.16 | 89.04 | 202.56 |

Signing time varies because ML-DSA signing is rejection-sampled; we report its median and
tail. With Wi-Fi running, level-3 signing on the bench took 38-250 ms (median 78) and a whole
handshake 329-545 ms (median 439, 9 of 9 successful; USB-powered bench runs, not energy
measurements, `paper/data/E_phase6/README.md`). [TODO: E1 needs at least five runs per board
before Table 2 is final.]

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
| One legitimate handshake | 9-65 mJ (80-560 ms; ML-DSA signing varies) | E_rig, n=1 per condition |
| One admitted FORGE HELLO (full verify, fails at the end) | ≈3.45 mJ per marked op, ≈3.9 mJ from the window mean | E5 rig (Section 8) |
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

**FORGE + ECHO** (`paper/CONTEXT_2026-10-24.md`, 2026-10-27, 10 runs, gate-v2 firmware): the
attacker echoes the cookie FORGE's resent HELLO received back, patches it into the cached
template, and reuses it.

| Defence | Extra F power (n=5) | F disposition | Legit success |
|---|---|---|---|
| cookie | +15.1 ± 2.4 mW (+2.5 %) | ≈545 spent (full verify), ≈40 challenged | 0.14 ± 0.32 |
| gate v2 | +16.0 ± 0.5 mW (+2.7 %) | ≈540 spent, ≈40 challenged | 0.13 ± 0.31 |
| (none, FORGE without ECHO, reference) | +19.0 ± 1.4 mW | ≈590 spent | 0.28 |

**The echoing forger defeats both COOKIE and GATE v2.** The attacker echoes only about 30
cookies per run, but the cookie as built is *reusable*: it is not bound to a HELLO's nonce or
(epoch, seq), so a single echoed cookie admits every later resend of the same cached template.
Gate v2's rule 2 ("a returned cookie admits whatever the score") lets the same HELLOs through.
This is a genuine weakness, not a result to be proud of, and we report it as one: binding the
cookie to the HELLO it was issued for, or making it single-use, would close it; that fix was not
made for this paper (it needs a firmware change and a rerun).

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

**The bound has not actually been tested on the rig, and we should not claim it has been.**
Under GATE v2, ADAPTIVE measured +25.5 ± 3.0 mW; without a defence it measured +28.9 ± 2.3 mW.
Both numbers happen to sit under the ≈51 mW worst case, but that is not evidence the bound did
anything: the bucket starts full (*B* = 20 J) and, at the placeholder's charges, no 120 s run in
this paper spent anywhere close to emptying it (Section 5's FORGE+ECHO arithmetic: ≈540 spends
× 0.02 J ≈ 10.8 J, against 20 J + 6 J of refill — well under capacity). The bound (1)-(2) is a
property of the bucket mechanics for *any* run long enough to matter; nothing here was. Worse,
the bound only ever caps what is *charged*, not what the handshake actually costs: a real
handshake on the mesh measured up to 65 mJ (Table 5) against a 20 mJ charge, so even a bucket
that does run dry would still undercount the victim's real drain by that gap. Both of these are
reasons to say the budget-bounded claim C3 is derived and consistent with what little data
exists, not demonstrated: a run of 10+ minutes at the placeholder's refill rate, with *c_h* set
to what a handshake (or a FORGE verify) actually costs, is the test this section still needs —
the FORGE+ECHO result (Section 8) is the closest attempt so far (≈540 admits per 120 s window
via GATE v2's rule 2), and even that did not run long enough to see rule 3 (DROP once exhausted)
engage.

## 9. EnergyGate on recorded traces

[TODO S7. Retrain on traces recorded from these boards, split by recording session (never
random), AUC and TPR at 1 % FPR next to the SIMULATED-trained model and a hand-tuned threshold
rule.]

## 10. Limitations

- **No battery.** The victim runs from a 5 V adaptor through the sensor; `battery_pct` is fixed
  at 100 (SIMULATED) and battery-life figures are derived from joules, not measured run-down.
- **Model trained on SIMULATED traces** with slightly different feature definitions from the
  firmware; until it is retrained on recorded traces (Section 9) its behaviour on real traffic is
  not a result.
- **Placeholder costs, now measured but not applied.** The joule budget's capacity and refill
  rate are still placeholders, and never emptied in any 120 s run in this paper (Section 8). The
  handshake cost placeholder (20 mJ) overcharges field-1's own measured share of a handshake
  (≈14.9 mJ, Table 4) by about 1.3x, and overcharges a failed FORGE verify (≈3.5-3.9 mJ) by
  about 5x; the challenge cost is below this rig's resolution as a positive measurement (bounded
  above at ≈0.4 mJ, Section 5). None of this was written back into the firmware for this paper —
  every run here used the original placeholders, and the budget-bounded claim C3 is derived, not
  demonstrated on the rig (Section 8).
- **Absolute energy depends on an unsettled reference.** The INA219 and the DT830D differ by
  3.67 % in gain and 1.4-3.1 % in voltage; ratios are unaffected.
- **Unauthenticated control channel.** GATE_REPORT, CONTROL and CHALLENGE travel in plaintext
  on the same radio the attacker shares; this is a lab rig.
- **The cookie is not just echoable but reusable.** It is bound to neither the HELLO's nonce nor
  its (epoch, seq), so a single echoed cookie admits every later resend of the same cached
  template (Section 8, FORGE + ECHO): the attacker echoed about 30 cookies per 120 s run but
  that admitted roughly 540 forged HELLOs. This is stronger than "an attacker can echo the
  cookie" — it means the budget, not the cookie or the gate's rule 2, is the only thing bounding
  an echoing attacker, and it does so (Section 8) but was not fully exercised in a 120 s window.
  Binding the cookie to the HELLO it was issued for would close this; not done for this paper.
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

[S4: from paper/writing/related_work.md. Position against Gillot et al. 2026, the ESP32-C6
PLOS ONE 2026 paper, Lee et al. 2026 (arXiv) and Hristozov et al.]

## 12. Conclusion

[After results.]

## Artifact

Repository layout for reviewers: `firmware/` (all board firmware, host tests), `ml/` (EnergyGate
training and export), `paper/data/` (raw logs, never edited; `paper/runlog.csv` lists every run,
excluded ones marked), `paper/analysis/` (scripts that rebuild every table), `paper/setup.md`
(rig and calibration record).
