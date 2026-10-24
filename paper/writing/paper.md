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

We evaluate three attacker behaviours (`paper/decisions.md`, Phase 6 #7):
- **FLOOD:** forged HELLOs claiming the gateway's id with random signature bytes. If
  admitted, each costs the victim reception of 20 frames plus one failing ML-DSA verification.
- **INSIDER:** HELLOs validly signed with an *enrolled* attacker key, modelling a compromised
  or hostile enrolled peer. Each admitted HELLO costs verification, encapsulation, a signature
  and a 19-frame RESPONSE.
- **SLOW_DRIP:** INSIDER at about one HELLO per minute, below any fixed rate limit.
- **Adaptive** (Section 8, task S5): knows EnergyGate's eight features and paces and shapes
  its traffic to stay above the score threshold. [TODO S5.]

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
handshake is charged *c_h*, a challenge *c_c*. Current values (`firmware/src/field_node/main.cpp`,
`sentinel_proto/gate_policy.h`) are all **PLACEHOLDERS** until the rig measures them:
*B* = 20 J, *r* = 0.05 J/s, *c_h* = 0.02 J, *c_c* = 0.0005 J. [TODO S2: replace *c_h* and *c_c*
with measured values and rerun.] When an admission is refused because the crypto task is busy,
its charge is refunded.

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

[TODO S2. Table 4: energy per operation (ML-KEM keygen/encaps/decaps, ML-DSA sign/verify,
AES-GCM per KB) at both levels, mean ± sd and 95 % CI over BENCH_REPEAT = 20 repetitions,
idle baseline subtracted (idle = 10 s before the first marker). Table 5: energy per accepted
handshake, per challenge and per dropped HELLO on the real mesh, including radio. Figure 1:
current trace of one handshake with phases marked.]

## 8. Results: the attack and the defences (C2, C3)

[TODO S3. Table 6: per defence × attack cell, victim joules in the attack window above
baseline, joules per forged HELLO, legitimate handshake success per attempt (mean, 95 % CI,
n ≥ 5), attacker joules (ESTIMATED from airtime until a second monitor exists) and the
ratio. Figure 2: victim power over time for each defence under FLOOD. Rate sweep (5, 20, 50
HELLO/s): where connectivity starts to fail. ECHO attacker against COOKIE and GATE.]

Bench observations so far (USB power, one run each, SIMULATED-trained model; context only,
not results): with no defence a 5/s flood made F verify about 560 forged HELLOs while all
9 of 9 legitimate handshakes still succeeded, so at that rate the flood costs the battery,
not connectivity; gate v2 challenged about 600 forged HELLOs, admitted about 2 at onset and
completed 9 of 9 legitimate handshakes (`paper/data/E_phase6/README.md`).

**Budget bound under an adaptive attacker.** [TODO S5: the analytic worst-case drain. Over a
long attack, admitted handshakes cost at most *B* + *r*·*T* budget joules in time *T*, so the
long-run rate of budgeted crypto spend cannot exceed *r* whatever the score says; plus the
unbudgeted per-frame reception cost. Turn this into victim watts with the measured *c_h* and
the per-frame cost from Section 7, and compare with the adaptive attacker's measured drain.]

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
- **Placeholder costs.** The joule budget, handshake cost and challenge cost are placeholders
  until replaced by measured values.
- **Absolute energy depends on an unsettled reference.** The INA219 and the DT830D differ by
  3.67 % in gain and 1.4-3.1 % in voltage; ratios are unaffected.
- **Unauthenticated control channel.** GATE_REPORT, CONTROL and CHALLENGE travel in plaintext
  on the same radio the attacker shares; this is a lab rig.
- **The cookie is echoable** on a broadcast medium; only the budget bounds an echoing attacker.
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
