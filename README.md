# SentinelMesh 🛡️⚡
### Energy-Aware Security for Post-Quantum IoT: Deciding Who Is Worth the Battery

[![Code Cortex 3.0](https://img.shields.io/badge/Hackathon-Code%20Cortex%203.0%20(Security%20Track)-blueviolet?style=flat-square)](https://github.com/ramkirangaruda/Sentinel-Mesh)
[![Firmware Tests](https://img.shields.io/badge/Firmware%20Tests-288%20Passing-brightgreen?style=flat-square)](firmware/test/)
[![Console Tests](https://img.shields.io/badge/Console%20Tests-99%20Passing-brightgreen?style=flat-square)](console/tests/)
[![ML--C Parity](https://img.shields.io/badge/ML%E2%86%92C%20Parity-500%2F500%20Verified-blue?style=flat-square)](ml/tests/)
[![Python](https://img.shields.io/badge/Python-3.12-blue?style=flat-square&logo=python)](ml/)
[![PlatformIO](https://img.shields.io/badge/Platform-ESP32%20%7C%20PlatformIO-orange?style=flat-square&logo=espressif)](firmware/)
[![React](https://img.shields.io/badge/UI-Vite%20%2B%20React%20%2B%20Tailwind-61DAFB?style=flat-square&logo=react)](console/web/)

---

> **The Core Thesis**  
> *Post-quantum cryptography protects the message, but nothing protects the battery. On constrained field devices, verifying large post-quantum signatures is computationally expensive and energy-intensive. An attacker who repeatedly sends forged requests can drain an endpoint's battery flat without ever breaking a cryptographic key. SentinelMesh measures that cost in joules on real hardware and implements **EnergyGate**—a lightweight, learned admission gatekeeper that decides, before performing cryptographic verification, whether an incoming connection is worth the battery.*

---

## Table of Contents

- [1. Executive Summary & Attack Chain](#1-executive-summary--attack-chain)
- [2. The v4 Research Breakthrough: Energy as the Attack Surface](#2-the-v4-research-breakthrough-energy-as-the-attack-surface)
  - [2.1 The Post-Quantum Asymmetry](#21-the-post-quantum-asymmetry)
  - [2.2 Contribution A: Hardware-Measured Energy Budget](#22-contribution-a-hardware-measured-energy-budget)
  - [2.3 Contribution B: EnergyGate (The Learned Gatekeeper)](#23-contribution-b-energygate-the-learned-gatekeeper)
  - [2.4 Contribution C: 5-Row Comparative Experiment](#24-contribution-c-5-row-comparative-experiment)
- [3. The Four Defense Layers](#3-the-four-defense-layers)
  - [3.1 L1 — MailGuard (Malicious Email Detection)](#31-l1--mailguard-malicious-email-detection)
  - [3.2 L2 — FileGuard (PE Executable Analysis)](#32-l2--fileguard-pe-executable-analysis)
  - [3.3 L3 — FieldGuard (Post-Quantum Radio Protocol & Anomaly Detection)](#33-l3--fieldguard-post-quantum-radio-protocol--anomaly-detection)
  - [3.4 L4 — TamperGuard (Physical Multi-Sensor Defense)](#34-l4--tamperguard-physical-multi-sensor-defense)
  - [3.5 Detection Channels: SMS Guard](#35-detection-channels-sms-guard)
- [4. Correlation Engine & Central Console](#4-correlation-engine--central-console)
- [5. System Architecture & Inter-Stream Contract](#5-system-architecture--inter-stream-contract)
- [6. Hardware Specification & Topology](#6-hardware-specification--topology)
- [7. Repository Structure](#7-repository-structure)
- [8. Quick Start & Execution Guide](#8-quick-start--execution-guide)
- [9. Verification & Automated Test Suites](#9-verification--automated-test-suites)
- [10. Honest Engineering & Methodological Transparency](#10-honest-engineering--methodological-transparency)

---

## 1. Executive Summary & Attack Chain

**SentinelMesh** is an integrated cyber-physical defense system engineered for **Code Cortex 3.0 (Security Track)**. It models and defends against the progression of the **23 December 2015 Ukraine Power Grid Cyberattack**, where adversaries executed a multi-stage intrusion: spear-phishing operators, executing malicious attachments, pivoting into industrial control networks, and attempting physical operational disruption.

Rather than deploying isolated, disconnected tools, SentinelMesh implements a purpose-built detector at each stage of the kill chain, feeding all events into a unified correlation engine:

```
[Attacker]
    │
    ▼ Stage 1: Phishing Vector
┌─────────────────────────────────────────────────────────────────┐
│ L1: MailGuard (NLP / Adversarial TF-IDF Classifier)             │  ──> [Event: email_malicious]
└─────────────────────────────────────────────────────────────────┘
    │
    ▼ Stage 2: Malicious Payload Execution
┌─────────────────────────────────────────────────────────────────┐
│ L2: FileGuard (LightGBM Static PE Structural Classifier)        │  ──> [Event: file_malicious]
└─────────────────────────────────────────────────────────────────┘
    │
    ▼ Stage 3: Field Radio Mesh Infiltration
┌─────────────────────────────────────────────────────────────────┐
│ L3: FieldGuard (Post-Quantum ESP-NOW Protocol + EnergyGate)     │  ──> [Event: replay/flood/gate]
└─────────────────────────────────────────────────────────────────┘
    │
    ▼ Stage 4: Substation Physical Access
┌─────────────────────────────────────────────────────────────────┐
│ L4: TamperGuard (Optical, Magnetic, Inertial, Voltage Sensors)   │  ──> [Event: case_opened/tamper]
└─────────────────────────────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────────────────────────────┐
│ SentinelMesh Correlation Engine & Operator SOC Console          │
│ • Deterministic Incident Synthesis (Rules R1-R5)               │
│ • Real-time Hardware Battery Telemetry & Projected Lifespan     │
└─────────────────────────────────────────────────────────────────┘
```

| Layer | Real-World Attack Stage | Primary Detection Target | Tech Stack & Mechanism |
|---|---|---|---|
| **L1 — MailGuard** | Initial Infiltration Vector | Phishing / Malicious Email | TF-IDF (1-2 n-grams) + Logistic Regression with adversarial padding defense |
| **L2 — FileGuard** | Endpoint Exploitation | Malicious PE Binaries (.exe / .dll) | LightGBM gradient-boosted trees over 54 structural PE-header features |
| **L3 — FieldGuard** | Mesh Network Intrusion | Handshake floods, replay, impersonation, energy-drain | Post-quantum wire protocol (ML-KEM + ML-DSA-44) + on-device C decision tree |
| **L4 — TamperGuard** | Physical Enclosure Tampering | Enclosure breach, relocation, electrical tampering | 4 physical sensor channels (LDR, Reed switch, MPU6050, Voltage anomaly) |
| **SOC Console** | End-to-End Visibility | Correlated Coordinated Incidents | FastAPI + SQLite + Vite/React UI + Streamlit Fallback + Serial Bridges |

---

## 2. The v4 Research Breakthrough: Energy as the Attack Surface

### 2.1 The Post-Quantum Asymmetry

As constrained IoT devices migrate to NIST post-quantum cryptographic (PQC) standards to defend against future quantum cryptanalysis, they introduce an acute physical vulnerability: **cryptographic operations and payload sizes grow by orders of magnitude**.

```
Classical Link (ECDSA / X25519)
├── Signature: 64 bytes
├── Public Key: 32 bytes
└── Handshake: 1 ESP-NOW Frame (Fits within 250B)

Post-Quantum Link (ML-DSA-44 / ML-KEM-1024)
├── ML-DSA-44 Signature: 2,420 bytes (~38x larger)
├── ML-KEM-1024 Public Key: 1,568 bytes (~49x larger)
└── Handshake: 14–18 ESP-NOW Fragments (235B payload each)
```

**The Threat:** In a battery-powered field sensor running off a single 18650 lithium cell (~2,600 mAh / ~34,000 J), an attacker holding **zero cryptographic keys** can bombard the gateway with spoofed or replayed `HELLO` packets. The field device must allocate reassembly buffers across 14–18 radio frames, execute post-quantum signature verification (`ML-DSA-44`), and run decapsulation (`ML-KEM`). **The attack is entirely asymmetric: the attacker expends microjoules of radio energy; the victim burns joules and exhausts its battery in hours.**

### 2.2 Contribution A: Hardware-Measured Energy Budget

To avoid theoretical estimates, SentinelMesh characterizes real cryptographic energy consumption directly on ESP32 microcontrollers using an isolated, non-invasive measurement rig:

```
[18650 Li-Ion Cell]
       │
       ▼
 [INA219 Sensor] (High-side in series on raw battery line, before boost regulator)
       │
       ├────────────────────────┐
       ▼                        ▼ (I2C Bus + Shared Ground)
[5V Boost Shield]       [ESP32 Monitor Board (Node D)]
       │                        ▲
       ▼ (5V/VIN)               │ (GPIO 4 Marker Pin: High during op, Low when done)
[ESP32 Node Under Test] ────────┘
```

- **Isolated Logging**: The measurement is conducted by an independent ESP32 **Monitor board** over I2C at ~1 kHz sampling rate. The target node never measures itself, preventing measurement self-consumption from skewing baseline data.
- **Microsecond Precision**: The node under test toggles a shared GPIO marker pin high precisely at the entry point of cryptographic routines and low upon exit.
- **Operations Characterized**:
  - `ML-KEM` KeyGen, Encapsulation, Decapsulation (512, 768, 1024)
  - `ML-DSA-44` Sign and Verify
  - `AES-256-GCM` Symmetric payload crypto per KB
  - Classical Baselines: `X25519` and `ECDSA/P-256` via mbedTLS
  - ESP-NOW Radio Airtime & Reassembly Overheads

### 2.3 Contribution B: EnergyGate (The Learned Gatekeeper)

Traditional intrusion detection operates *post-facto* (after packet processing), which fails against energy-drain attacks because processing the packet causes the damage. **EnergyGate** runs **prior to cryptographic verification**, utilizing **8 zero-cost signals** derived from free hardware and link-layer metadata:

```
                        Incoming Radio Request (HELLO)
                                      │
                                      ▼
                        ┌───────────────────────────┐
                        │ Free Feature Vector (x8)  │
                        │ • rssi_mean, rssi_var     │
                        │ • hs_per_s (arrival rate) │
                        │ • hs_fail (failure proxy) │
                        │ • frag_complete_pct       │
                        │ • loss_pct, dup_pct       │
                        │ • battery_pct             │
                        └─────────────┬─────────────┘
                                      │
                                      ▼
                        ┌───────────────────────────┐
                        │ EnergyGate Decision Tree  │
                        │ Exported to pure C        │
                        │ 423 B flash, no static RAM│
                        └─────────────┬─────────────┘
                                      │
                                      ▼ P(real) ∈ [0, 1]
                                      │
         ┌────────────────────────────┴────────────────────────────┐
         │ Firmware Dynamic Policy (Evaluating against live Joules)│
         │ - Live Token Bucket Balance (Refilling Joules)          │
         │ - Configurable Spend / Challenge / Drop Thresholds      │
         └─────────────┬─────────────────────────────┬─────────────┘
                       │                             │
          High P(real) & Budget OK      Moderate P(real) / Low Budget    Low P(real) / Exhausted
                       ▼                             ▼                             ▼
                 [ SPEND ]                     [ CHALLENGE ]                    [ DROP ]
           Perform full ML-KEM +        Stateless 8-byte DTLS cookie       Zero-cost silent drop;
           ML-DSA-44 handshake;         challenge (~40 bytes total).       record telemetry event
           deduct Joules from bucket.   Blocks spoofed flooders.           to SOC console.
```

- **C Export, Parity-Checked**: The decision tree is trained in Python (`scikit-learn`) and exported as a pure C function (`float energygate_score(const float*)`) with no dynamic memory allocation and no inference engine. An automated test compiles the header with `gcc` and compares it to scikit-learn on 500 boundary-stressing feature vectors; the probabilities agree to float rounding (tolerance 1e-4, measured worst case 2e-7 on the shipped model). That shows the export is faithful, not that the model is accurate.
- **Current status: trained on SIMULATED traces.** No real board recordings exist yet, so the tree compiled into field-1 (`energygate_model.h`) was trained on our own simulated windows (overlapping classes, noise, 3% label noise). Held out by recording session it reaches AUC 0.947 on that simulated data, which measures our generator, not real attackers; in simulation two features (`hs_fail`, `dup_pct`) do nearly all the work (`ml/reports/model_cards.md`). The scoring code is 423 B of flash on the ESP32; inference time and energy have not been measured yet, which is what the INA219 rig is for. Retrain on recorded traces with `make energygate` before quoting any accuracy.
- **Clean Architectural Separation**: The ML model calculates *plausibility* ($P(\text{real})$); the microcontroller firmware evaluates that score against its *live physical energy reserve* (the Joule token bucket).

### 2.4 Contribution C: 5-Row Comparative Experiment

To rigorously validate EnergyGate, SentinelMesh benchmarked five distinct defensive configurations subjected to identical simulated adversarial profiles:
1. **Loud Flood**: High-frequency packets per second.
2. **Slow Drip**: ~1 handshake request per minute—specifically engineered to evade static rate-limiting thresholds while steadily depleting battery reserves over weeks.

| Defense Condition | Attack Profile | Energy Drain (J/hr) | Projected Battery Life | Legit Node Admitted? | Added Latency (Legit) |
|---|---|---|---|---|---|
| **1. Baseline (No Attack)** | None | *Measured* | *Nominal (Months)* | Yes | 0 ms |
| **2. Unprotected Link** | Loud Flood / Slow Drip | *Max Drain* | *Severely Degraded (Hours)* | Intermittent | Severe (Buffer starvation) |
| **3. Static Rate Limiting** | Slow Drip | *High Drain* | *Degraded* | Yes | Low |
| **4. Cookie Challenge Only** | Coordinated Flood | *Low-Medium* | *Extended* | Yes (after retry) | 1 RTT (~40 ms) |
| **5. EnergyGate (Adaptive)** | Loud Flood + Slow Drip | *Near-Baseline* | *Maximum Preservation* | Yes | gate cost not yet measured |

> [!IMPORTANT]
> This table states the design's *expected* outcomes, not measurements. Real values come only from the INA219 rig (`docs/hardware_setup.md`); anything produced by the mock rig is tagged `source: "sim"` and shown as SIMULATED in the console. Row 5 also inherits the model status in section 2.3: its tree is currently trained on simulated traces.

> [!NOTE]
> The console UI provides an interactive **Battery Discharge Curve** tracking three concurrent projections: *Unprotected*, *No Attack Baseline*, and *Protected by EnergyGate*, directly visualizing battery life extended from hours to months.

---

## 3. The Four Defense Layers

### 3.1 L1 — MailGuard (Malicious Email Detection)
- **Model**: TF-IDF (unigrams & bigrams, parameterized placeholder tokens for URLs, email addresses, and numerical values) paired with an L2-regularized Logistic Regression classifier.
- **Dataset**: 75,631 de-duplicated emails aggregated across 5 public corpora: `CEAS_08`, `Enron`, `Ling`, `Nigerian_Fraud`, and `SpamAssassin`.
- **Honest Evaluation & Generalization**:
  - Random 70/15/15 Split (15% test): **~98% Accuracy** (1.8% False Positive Rate).
  - **Leave-One-Corpus-Out (Strict Generalization)**: **87.6% – 94.5% Accuracy** across unseen email writing styles.
  - **Adversarial Hardening**: Defends against filler-text padding attacks. Padding a malicious email with ordinary text collapsed recall from 99.3% to 15.8%; adversarial training on padded copies recovers it to 79.1% at a 1.5% false-alarm rate. Layouts it never trained on (padding before and after, interleaved) still evade it about half the time or more, and broader hardening was tried and reverted because it hurt accuracy on unseen email sources (`ml/reports/model_cards.md`).
  - **Threshold Does Not Transfer**: tuned for at most 2% false alarms on data like the training data, the threshold gives 7.5% to 25.9% false alarms on a held-out corpus (`ml/reports/experiments.json`).
- **Explainability**: Outputs the top three feature weights per prediction mapped to human-readable strings (e.g., *"Urgent payment phrasing"*, *"Suspicious credential request"*), powering the operator dashboard's "Why" panel.

### 3.2 L2 — FileGuard (PE Executable Analysis)
- **Model**: LightGBM gradient-boosted decision tree ensemble trained on **54 static PE-header structural features** (section entropy, optional headers, import address table characteristics, relocations) extracted using `pefile`.
- **Dataset**: 138,047 Windows PE binaries (~70% malicious, 30% benign).
- **De-Biasing & Benchmark Rigor**:
  - Group-split validation based on feature hashes prevents data leakage from near-identical binaries (35,856 duplicate feature vectors isolated).
  - **The Third-Party Software Bias Discovery**: When tested against 1,566 modern benign binaries across 198 `pip` and `npm` native packages, the raw baseline model triggered a **40.5% False Positive Rate**. The team augmented and re-weighted the benign distribution, successfully cutting the false alarm rate to **0.44%** while preserving **98.94% detection at 0.1% FPR**.
  - Documented Limitation: 64-bit malware accounts for only 68 out of 96,724 training samples; model is explicitly documented as tuned for 32-bit PE binaries.
  - **Unseen Malware Families**: the shipped split groups only identical feature vectors. Holding out whole clusters of similar files (k-means, k=300, 5 seeds) drops detection at 0.1% FPR from 98.5% ± 0.3% to **88.1% ± 7.2%**. Quote the 88% for malware unlike anything in training; clusters are a proxy for families, not labelled families.
  - **`ImageBase` Shortcut Checked**: one column carries 74% of the gain, but retraining without the top-5 gain columns moves detection at 0.1% FPR only from 98.5% to 98.1%, so it is not a single fixable shortcut (`ml/reports/model_cards.md`).

### 3.3 L3 — FieldGuard (Post-Quantum Radio Protocol & Anomaly Detection)
- **Wire Protocol**: Lightweight ESP-NOW framing featuring a 15-byte packed binary header (`epoch: uint16`, `seq: uint32`, `sender_id`, `frag_index`, `frag_total`, `msg_type`, `timestamp`).
- **Fragmentation Engine**: Transmits up to 235 bytes of payload per frame (within ESP-NOW's 250-byte maximum frame budget). Manages in-order, out-of-order, duplicate, and stale packet assemblies with automatic buffer eviction timeouts.
- **Cryptographic Engine**:
  - Handshake: 3-way authenticated key exchange (`HELLO`, `RESPONSE`, `CONFIRM`).
  - Key Exchange: `ML-KEM-512`, `ML-KEM-768`, or `ML-KEM-1024` (adaptively selected based on link health and battery state).
  - Authentication: Digital signatures via `ML-DSA-44` (with fallback to `HMAC-SHA256-PSK` if constrained execution limits require).
  - Session Encryption: Symmetric authenticated cipher via `AES-256-GCM`.
- **Sliding-Window Replay Protection**: 64-bit sliding window bitmap per peer paired with monotonic sequence validation and timestamp freshness filtering.
- **On-Device Anomaly Detection**: A decision tree over 5-second rolling window metrics (10 features: `hs_per_s`, `hs_fail`, `replay_rej`, `auth_fail`, `stale`, `frag_timeout`, `rssi_mean`, `rssi_var`, `loss_pct`, `jitter_ms`) classifying traffic into `normal`, `weak_link`, `replay`, `flood`, or `impersonation`.
- **Current status**: the board currently runs a hand-written rule-based classifier with placeholder thresholds (`field_model.h`). The training pipeline (train, C export, `gcc` parity check) is built and verified on synthetic data, but the tree has not been trained on recorded traces yet, so there is no measured FieldGuard accuracy to quote. `make test-feature-order` guards the feature order shared by the firmware and the trainer.

### 3.4 L4 — TamperGuard (Physical Multi-Sensor Defense)
The battery-powered field sensor node incorporates **four independent physical tamper-sensing channels** to prevent physical bypass:
1. **Light Dependent Resistor (LDR)**: Pinpointed optical threshold detecting enclosure opening.
2. **Magnetic Reed Switch**: Detects case separation even if an attacker attempts access in complete darkness.
3. **MPU6050 6-Axis Accelerometer/Gyroscope**: Flags physical movement, lifting, or relocation of the valve sensor.
4. **Voltage Anomaly Detection**: Monitors high-frequency battery bus deviations to detect battery swap attacks, hardware clip-ons, or forced short-circuits.

**Immediate Hardware Tamper Response**:
Upon trip detection on any channel, `field_node` triggers:
- Zeroization: volatile session keys are immediately overwritten in SRAM.
- Epoch Invalidation: increments session `epoch`, permanently invalidating the current replay window.
- Immediate Gateway Notification: transmits an authenticated critical tamper event over the mesh before re-initiating a fresh handshake.

### 3.5 Detection Channels: SMS Guard (extensibility demo)
The console has a pluggable **Detection Channels** registry (`channels/*/manifest.json`, `GET /channels`, `POST /classify`). MailGuard and FileGuard appear as reference entries; **SMS Guard** is a real classifier trained on the UCI SMS Spam Collection (word + character TF-IDF into logistic regression, the same model family as MailGuard); WhatsApp, Telegram and Voice are labelled dummy entries with no model, and `/classify` refuses them.
- **Held-out test (1,035 messages, 131 spam)**: 96.2% spam recall, 2.5% false alarms on legitimate messages, 84.6% precision, AUC 0.996. Repeated 5-fold cross-validation (15 fits, threshold re-tuned in every fold) gives the fairer range: recall 95.7% ± 2.5, false alarms 1.5%, **precision 90.9% ± 5.3 (79.5% to 97.6%)**, i.e. roughly 1 flag in 11 is a legitimate message.
- **Limits**: no held-out source (cross-validation only re-splits the one collection); old, generic UK/Singapore spam labelled "smishing" rather than modern smishing; and legitimate messages containing digits are flagged about 5x as often as those without (6.0% vs 1.1%; a rehearsed appointment-reminder fixture scores 0.895 and is flagged). Details in `ml/reports/model_cards.md`.

---

## 4. Correlation Engine & Central Console

The SentinelMesh console aggregates alerts from all four layers into actionable incident reports using a **transparent, auditable deterministic rule engine** (Rules R1–R5), rather than opaque second-tier machine learning:

```
[L1: MailGuard Alert] ──┐
[L2: FileGuard Alert] ──┼──> [FastAPI Ingestion] ──> [Schema Validator] ──> [Correlation Engine]
[L3: FieldGuard Alert] ─┼                                                        │
[L4: TamperGuard Alert] ─┘                                                        ▼
                                                                        [Synthesized Incident]
                                                                        • Sliding 10-min window
                                                                        • Severity Escalation
                                                                        • ATT&CK Technique Mapping
```

- **Rule R1 (Informational Filtering)**: Routine informational events and continuous `gate_decision` telemetry streams are recorded for logging but never instantiate security incidents on their own.
- **Rule R2 (Temporal Proximity)**: Security events occurring across any layer within a rolling 10-minute window are consolidated into a single unified incident.
- **Rule R3 (Severity Initialization)**: The incident inherits the highest severity level among its constituent events.
- **Rule R4 (Multi-Layer Escalation)**: If alerts originate from two or more distinct defensive layers within the temporal window, overall severity escalates by one tier (e.g., `MEDIUM` $\to$ `HIGH`).
- **Rule R5 (Coordinated Attack Synthesis)**: If events from **MailGuard**, **FileGuard**, and **FieldGuard** fire concurrently, the engine immediately flags a **Critical Coordinated Infrastructure Attack** (matching the historical Ukraine power grid sequence).

### Operator Interfaces

1. **React SOC Operations Dashboard (`console/web/`)**:
   - Built with Vite, React, Tailwind CSS v4, and Recharts.
   - Real-time incident feeds with MITRE ATT&CK mappings.
   - Dynamic battery discharge curves comparing live consumption vs. baselines.
   - Interactive demo control triggers to command gateway defense modes and attacker profiles.
2. **Streamlit Fallback Console (`console/ui/`)**:
   - Runs independently on port 8501 as a backup operator UI.
   - Integrated **Trace Recording Studio** to capture and label 5-second radio telemetry windows directly into training datasets.

---

## 5. System Architecture & Inter-Stream Contract

SentinelMesh was developed using a strict **multi-stream contract-driven architecture**, allowing machine learning, console, and firmware engineering streams to execute in parallel without integration collisions:

```
┌────────────────────────────────────────────────────────────────────────┐
│                   Shared Integration Contract                          │
│     contracts/CONTRACT.md  •  JSON Schemas: Event, Trace, Energy       │
└────────────────────────────────────────────────────────────────────────┘
          │                                 │                  │
          ▼                                 ▼                  ▼
┌──────────────────┐               ┌─────────────────┐ ┌─────────────────┐
│ Stream 1: ML     │               │ Stream 2: CON   │ │ Stream 3: FW    │
│ (ml/)            │               │ (console/)      │ │ (firmware/)     │
│ • MailGuard      │               │ • FastAPI API   │ │ • field_node    │
│ • FileGuard      │               │ • React UI      │ │ • gateway       │
│ • EnergyGate     │               │ • Bridges       │ │ • attacker      │
│ • Exported C h   │               │ • SQLite Store  │ │ • INA219 monitor│
└──────────────────┘               └─────────────────┘ └─────────────────┘
```

### The Standardized Event Schema
Every alert emitted across all four layers conforms to `contracts/event.schema.json`:
```json
{
  "id": "urn:uuid:7c9e6679-7425-40de-944b-e07fc1f90ae7",
  "ts": 1726651200000,
  "layer": "field",
  "type": "gate_decision",
  "severity": "info",
  "score": 0.892,
  "node": "gateway",
  "technique": "T0830",
  "summary": "EnergyGate permitted post-quantum handshake (P(real)=0.892)",
  "reasons": ["Normal packet cadence", "Consistent RSSI variance", "Zero fragment timeouts"],
  "details": {
    "action": "spend",
    "budget_remaining_j": 42.15
  }
}
```

### Serial Wire Communication
The gateway ESP32 communicates with the console laptop over USB serial at **115200 baud**:
- `EVT <json>`: Emitted by gateway to log structured alerts.
- `TRC <json>`: Emitted every 5 seconds carrying telemetry counters for model training.
- `NRG <json>`: Emitted by the monitor board carrying INA219 voltage, current, and power metrics.
- `DEFENSE <none|ratelimit|cookie|gate>`: Console command setting the gateway admission policy.
- `MODE <OFF|REPLAY|FLOOD|IMPERSONATE|WEAK_LINK|SLOW_DRIP>`: Console command instructing the attacker board.

---

## 6. Hardware Specification & Topology

```
   ┌───────────────────────────┐                ┌───────────────────────────┐
   │        Node A             │    ESP-NOW     │        Node B             │
   │      field_node           │ ◄────────────► │        gateway            │
   │ (Battery-Powered Sensor)  │   Radio Link   │ (USB Link to SOC Laptop)  │
   └─────────────┬─────────────┘                └─────────────┬─────────────┘
                 │                                            │
                 ▼                                            ▼ USB Serial (115200)
   ┌───────────────────────────┐                ┌───────────────────────────┐
   │        Node D             │                │    Operator SOC Laptop    │
   │        monitor            │                │ • FastAPI Backend (:8000) │
   │ (INA219 Isolated Rig)     │                │ • React Console (Web)     │
   └───────────────────────────┘                │ • Streamlit UI (:8501)    │
                                                └───────────────────────────┘
   ┌───────────────────────────┐                              ▲
   │        Node C             │                              │
   │        attacker           │ ─────────────────────────────┘ USB Serial (Control)
   │ (Red-Team RF Transmitter) │
   └───────────────────────────┘
```

### Physical Pin Configurations

#### Field Node (`field_node`)
- **Microcontroller**: ESP32-WROOM-32
- **Power**: 18650 Li-ion Cell $\to$ INA219 (high-side shunt) $\to$ 5V Boost Shield $\to$ VIN
- **I2C Bus (SDA/SCL)**: GPIO 21 / GPIO 22 (shared between 0.96" SSD1306 OLED & MPU6050)
- **Optical Tamper (LDR)**: GPIO 34 (Analog input)
- **Magnetic Tamper (Reed Switch)**: GPIO 27 (Digital active-low pullup)
- **RGB Status LED**: Red: GPIO 25, Green: GPIO 26, Blue: GPIO 13 (220Ω series resistors)
- **Audible Alert (Buzzer)**: GPIO 33
- **Interactive Inputs**:
  - Urgent PQC Escalation Button: GPIO 32
  - Auxiliary "Weak Link" Trigger: GPIO 35
- **Battery Divider**: GPIO 39 (100kΩ / 100kΩ resistor divider network)

#### Gateway Node (`gateway`)
- **Microcontroller**: ESP32-WROOM-32 (USB Powered via Console Workstation)
- **I2C Display**: SSD1306 OLED on GPIO 21 / GPIO 22
- **Status Indicators**: RGB LED (GPIO 25, 26, 13) + Buzzer (GPIO 33)

#### Energy Monitor Node (`monitor`)
- **Microcontroller**: ESP32-WROOM-32
- **INA219 Power Monitor**: I2C bus (GPIO 21 / 22)
- **Marker Input**: GPIO 4 tied directly to Node A / Node B marker pin
- **Common Ground**: Mandatory common GND line bridging the target node and monitor

---

## 7. Repository Structure

```
Sentinel-Mesh/
├── contracts/                  # Frozen Cross-Stream Contracts & Schemas
│   ├── CONTRACT.md             # Transport, line format, and endpoint specifications
│   ├── event.schema.json       # JSON schema for multi-layer Event alerts
│   ├── trace.schema.json       # JSON schema for 5-second radio telemetry rows
│   └── energy.schema.json      # JSON schema for INA219 current/power samples
│
├── ml/                         # Stream 1: Machine Learning & On-Device Models
│   ├── sentinel_ml/            # Core library: MailGuard, FileGuard, EnergyGate, parsers
│   ├── benign/                 # Benign third-party binary extraction and feature builder
│   ├── export/                 # Generated pure-C headers (energygate.h, field_model.h)
│   ├── models/                 # Serialized production models (mailguard.joblib, etc.)
│   ├── reports/                # Model cards, training evaluations, and metrics.json
│   ├── build_all.py            # End-to-end training pipeline for L1 and L2
│   ├── service.py              # FastAPI microservice for scoring emails and binaries (:8001)
│   └── Makefile                # Targets for training and validating C-export parity
│
├── console/                    # Stream 2: Operator Console & Correlation Engine
│   ├── api/                    # FastAPI core backend, SQLite ORM, schema validation
│   │   ├── main.py             # Event router and server entrypoint (:8000)
│   │   └── correlation.py      # Deterministic incident correlation rules (R1–R5)
│   ├── bridge/                 # Stateless serial bridge forwarding between ESP32 and HTTP
│   ├── web/                    # Production React operator frontend (Vite, hand-written CSS)
│   ├── ui/                     # Streamlit fallback operator UI + trace recorder (:8501)
│   ├── tools/                  # Hardware-in-the-loop mock stand-in tools
│   │   ├── mock_rig.py         # Simulated INA219 reactive energy telemetry
│   │   ├── mock_serial.py      # Virtual serial generator for EVT/TRC/NRG streams
│   │   └── mock_events.py      # Full 5-stage Ukraine incident simulator
│   └── tests/                  # 89 automated pytest tests covering rules, API, and schemas
│
├── firmware/                   # Stream 3: ESP32 Embedded C++ Firmware
│   ├── lib/sentinel_proto/     # Portable C++ core wire protocol & algorithms
│   │   ├── include/sentinel_proto/
│   │   │   ├── packet.h        # 15-byte packed wire framing
│   │   │   ├── fragment.h      # 235-byte fragmentation and reassembly engine
│   │   │   ├── replay.h        # 64-bit sliding window replay filter
│   │   │   ├── cookie.h        # Stateless DTLS-style return-routability cookie
│   │   │   ├── energy_budget.h # Joule-denominated token bucket implementation
│   │   │   └── energygate.h    # Embedded EnergyGate scoring interface
│   ├── src/
│   │   ├── field_node/         # Node A: Sensor acquisition, adaptive PQC, tamper routines
│   │   ├── gateway/            # Node B: Admission control, EnergyGate execution, bridge
│   │   ├── attacker/           # Node C: Red-team radio transmitter (Flood, Replay, Slow Drip)
│   │   ├── monitor/            # Node D: INA219 high-rate energy characterization rig
│   │   └── benchmark/          # PQC vs. Classical cryptographic execution benchmark
│   ├── test/test_native/       # 206 native C++ host unit tests (no hardware required)
│   └── platformio.ini          # PlatformIO multi-environment configuration
│
└── docs/                       # Technical Specifications & Guides
    ├── hardware_setup.md       # Step-by-step physical bring-up and safety manual
    └── v4_energy_split.md      # Detailed task and interface boundaries for v4 energy work
```

---

## 8. Quick Start & Execution Guide

### Prerequisites
- **Python**: Version 3.10+ (Python 3.12 recommended)
- **Node.js**: Version 18+ & npm
- **C++ Toolchain**: `g++` / `clang++` (for native firmware unit tests) or **PlatformIO** (for ESP32 deployment)

> [!IMPORTANT]
> Always bind services to `127.0.0.1` rather than `localhost` on Windows/macOS to avoid IPv6 dual-stack resolution latency stalls (measured reduction from 2047 ms to 2.4 ms per call).

### Step 1: Set Up & Launch the ML Scoring Service
```bash
cd ml
python3 -m venv .venv
source .venv/bin/activate       # Windows: .venv\Scripts\activate
pip install -r requirements.txt

# Start the ML inference service on port 8001
uvicorn service:app --host 127.0.0.1 --port 8001
```

### Step 2: Set Up & Launch the SentinelMesh Console
In a new terminal:
```bash
cd console
python3 -m venv .venv
source .venv/bin/activate       # Windows: .venv\Scripts\activate
pip install -r requirements.txt

# Build the React production frontend
cd web
npm install
npm run build
cd ..

# Launch FastAPI Console on port 8000 (serves API and compiled React dashboard)
python -m uvicorn api.main:app --host 127.0.0.1 --port 8000
```
Open **`http://127.0.0.1:8000`** in your browser to access the live SOC dashboard.

### Step 3: Run Full End-to-End Simulation (No Hardware Needed)
If physical ESP32 boards are not connected, SentinelMesh provides interactive mock stand-ins that mirror hardware and RF traffic:

```bash
# Terminal 3: Stream simulated energy telemetry and admission decisions
cd console
python tools/mock_rig.py

# Terminal 4: Simulate the 2015 Ukraine Power Grid attack sequence
python tools/mock_events.py --speed 2
```

### Step 4: Connecting Physical ESP32 Hardware
When physical boards are flashed and connected via USB:
```bash
# Launch serial bridge for the Gateway ESP32 (e.g., /dev/ttyUSB0 or COM3)
python -m bridge.serial_bridge --port /dev/ttyUSB0 -v

# (Optional) Launch serial bridge for the Monitor Board
python -m bridge.serial_bridge --port /dev/ttyUSB1 -v
```

---

## 9. Verification & Automated Test Suites

SentinelMesh maintains comprehensive automated test coverage across all three engineering disciplines:

### 1. Firmware Protocol Unit Tests (Native Host Execution)
Execute 288 native C++ unit tests without hardware:
```bash
cd firmware
bash tools/run_native_tests.sh
```
*Coverage: Wire format packing, fragment assembly out-of-order handling, sliding-window replay filter, DTLS cookie generator, Joule token-bucket mechanics, and embedded decision tree scoring.*

### 2. Machine Learning Export Parity Verification
Verify that the generated C decision trees match the Python scikit-learn models, and that the firmware and the trainers agree on feature order:
```bash
cd ml
make test-energygate
make test-field-model
make test-feature-order
```
*Coverage: compiles the exported header with `gcc`, runs 500 boundary-stressing feature vectors through both scikit-learn and the native C build, and asserts they agree (EnergyGate: probabilities within 1e-4, measured worst case 2e-7; FieldGuard: identical class). These tests use SYNTHETIC data, so they show the export is faithful, not that a model is accurate. `test-feature-order` reads the feature order documented in the firmware headers and compares it index for index to the trainers.*

### 3. Console & Correlation Engine Test Suite
Run 99 automated pytest tests verifying schema compliance and correlation rules:
```bash
cd console
pytest tests/ -q
```
*Coverage: Contract validation against JSON schemas, correlation rules R1 through R5, SQLite persistence, and REST API route handling.*

---

## 10. Honest Engineering & Methodological Transparency

A core tenet of SentinelMesh is absolute methodological honesty. In engineering environments and technical evaluations, unstated assumptions and cherry-picked metrics undermine credibility:

1. **Malware Safety Protocol**:
   No live malware binaries are ever downloaded, stored, or executed. Malicious file testing uses pre-extracted static PE-header feature vectors from held-out sets. Scans on live files are performed solely on verified benign binaries.
2. **Generalization Over Random-Splits**:
   A random 70/15/15 split reports an overly flattering **~98%** accuracy on emails. We explicitly report **leave-one-corpus-out accuracy (87.6% – 94.5%)**, demonstrating true generalization to new writing styles.
3. **Transparent Bias Identification and Mitigation**:
   We openly document that our initial PE-malware model suffered a **40.5% false-alarm rate** on benign modern development packages (`pip`/`npm`), and demonstrate how we engineered a de-biasing distribution to cut that rate to **0.44%**.
4. **Distinction Between Simulation and Physical Ground Truth**:
   All telemetry produced by mock scripts is tagged with `source: "sim"`. The console UI displays a prominent **SIMULATED** badge on synthetic graphs to ensure illustrative mock data is never mistaken for physical hardware measurements.
5. **Pre-Planned Hackathon Cut Order**:
   Prioritized fallback boundaries were defined before the final integration hours:
   1. *Cut 1*: Physical radio fingerprinting (scoped, flagged data schema bottleneck, cleanly deferred).
   2. *Cut 2*: Slow-drip automated profile.
   3. *Cut 3*: Learned EnergyGate model (fallback to cookie-challenge + static rate limit while reporting honest measured baseline numbers).
   4. *Never Cut*: Ground-truth energy measurements, the 5-row comparative experiment, the authenticated handshake, and replay-window verification.
6. **Claims We Stress-Tested and Corrected**:
   Before finalizing, we attacked our own numbers and wrote down what broke (`ml/experiments/`, `ml/reports/experiments.json`, `ml/reports/model_cards.md`): the padding-evasion attack (one layout is still an open gap); MailGuard's false-alarm threshold not transferring to a new corpus; FileGuard dropping to 88% on unseen malware clusters; SMS Guard flagging some legitimate messages that contain numbers; and EnergyGate and FieldGuard being trained on simulated data only, so we claim no accuracy for them.

---

### License & Attribution
Developed for **Code Cortex 3.0 (Security Track)** by Team SentinelMesh.  
Built upon open post-quantum primitives (`ML-KEM`, `ML-DSA`), PlatformIO, and the FastAPI / React ecosystems.
