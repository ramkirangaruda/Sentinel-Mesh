# Related work (task S4, written 2026-10-24)

Owner: person S. Feeds Section 11 of `paper/writing/paper.md` and the `[CITE]` markers there.

**Status of every entry.** Entries marked **read** were opened and the abstract or page summarised on 2026-10-24
(the full text of none was read: details below are from the abstract/landing page unless stated). Entries marked
**snippet** come from search-result summaries only. **memory** means cited from the author's background knowledge and
not re-checked in this session: verify before citing. Nothing here has been read in full yet; do that for the four
anchor papers before the related-work section is written for submission.

## 1. The four anchor papers named in WORK_SPLIT

| Anchor | Found? | Notes |
|---|---|---|
| Gillot et al. 2026 | yes, two papers | see rows G1, G2 below |
| ESP32-C6 PLOS ONE 2026 | yes | Karcz et al., row P1 |
| Lee et al. 2026 (arXiv) | yes, probably | Lin-Fa Lee et al., row L1. It is about TLS on a server, not IoT: confirm with the team that this is the paper meant |
| **Hristozov et al.** | **not found** | Four searches (author + post-quantum, ESP32, DoS, energy) returned no paper by an author of that name. **Ask the team for the title, venue or year. Do not cite until it is located.** |

## 2. Table: closest prior work

| ID | Paper | Platform | What they measured | What they leave open (relative to us) | Status |
|---|---|---|---|---|---|
| G1 | Gillot, Buchanan, Tehrani. *Energy Consumption of Post-Quantum Cryptography on Constrained and General-Purpose Architectures*. Cryptography 10(4):55, 2026; ePrint 2026/2557; arXiv 2610.27111 | Raspberry Pi 1, Zero, 4 and laptops, OpenSSL 3.5 | Time and energy of ML-KEM, ML-DSA, SLH-DSA keygen/sign/verify, FNIRSI FNB58 USB power meter. ML-KEM and ML-DSA comparable to elliptic-curve cryptography; SLH-DSA signing up to 243 % more energy on 32-bit than 64-bit | Linux-class single boards, not a microcontroller; primitives only (no radio, no protocol); USB meter rather than a calibrated shunt on a bare board; no attacker | read (abstract) |
| G2 | Gillot, Buchanan, Turino. *Testing TLS 1.3 PQC on constrained devices and microcontrollers*. arXiv 2610.27766, Oct 2026 | Pico W, Pico 2 W, ESP32 (variant not stated on the page), Pi Zero; wolfSSL | Handshake latency and energy for a 36-combination TLS 1.3 matrix. ML-KEM-512 + ML-DSA-44 faster than X25519 + RSA-PSS (41 % on Pico W, 8.9x on ESP32), up to 2.12x energy-efficient on Pico W; ML-DSA signing time varies | **Closest to our C1.** Benign handshakes over TLS, not a custom ESP-NOW mesh; no adversary, so no cost of a handshake the victim did not want; how energy was measured not confirmed from the page | read (abstract) |
| P1 | Karcz, Niemiec, Kourtis, Köppl. *Exploring hardware implementation feasibility of post-quantum cryptography in embedded systems: Evaluation of NIST-standardized ML-KEM, ML-DSA and SLH-DSA on ESP32-C6*. PLOS ONE, 18 Aug 2026 | ESP32-C6 (RISC-V, 160 MHz, 512 KB), liboqs 0.14.0, ESP-IDF 5.5.1 | Execution time (100 runs for ML-KEM/ML-DSA), heap, flash, with sensor and BLE/Wi-Fi background load | **Energy not measured** (inferred from time; listed as future work). No handshake, no radio cost, no DoS. Different chip (RISC-V) from ours (Xtensa ESP32) | read (page) |
| L1 | Lee, Chang, Yu, Yeh. *On the Security Implications of PQC in TLS: Handshake Exhaustion and IDS Degradation*. arXiv 2607.12504, Jul 2026 | AWS: one PQC-TLS 1.3 server, ten attack nodes | PQC-TLS prolongs sustained high server CPU utilisation by up to 88x under handshake exhaustion; two deep-learning IDSs degrade (about 50 % recall; AU-ROC 0.49) | Server CPU, not battery energy; no constrained device; the defence evaluated is existing IDSs, not an admission gate in front of the handshake. **Supports our premise** that PQC amplifies handshake exhaustion | read (page) |
| H1 | Hummen, Wirtz, Ziegeldorf, Hiller, Wehrle. *Tailoring end-to-end IP security protocols to the Internet of Things*. ICNP 2013 | constrained IoT devices; DTLS, HIP DEX, minimal IKEv2 | Public-key operations hamper availability and response time during a handshake; proposes session resumption, a collaborative puzzle-based DoS protection and refined retransmission for HIP DEX | **Closest prior idea to our defence**: protect a constrained peer's public-key work from DoS. Pre-quantum primitives, puzzle not a learned score, no energy budget, no joule measurement of the attack | snippet |
| R1 | Radem et al. (H-BRS). *Analyzing power consumption of TLS ciphers on an ESP32*. 2019 | ESP32 | Current probe, energy per TLS cipher suite over 200 runs; full TLS session about 14x the energy of unencrypted transmission; ECDSA cheaper than RSA | Pre-quantum, benign traffic only. **Method precedent** for ESP32 handshake energy | snippet |
| S1 | Pirretti, Zhu, Vijaykrishnan, McDaniel, Kandemir, Brooks. *The Sleep Deprivation Attack in Sensor Networks: Analysis and Methods of Defense*. Int. J. Distributed Sensor Networks 2(3):267-287, 2006 | wireless sensor networks | Attack that sends just enough requests to keep nodes awake nullifies sleep savings; compares cluster-head selection defences (hash-based best) | Attack at the clustering/MAC level; not a cryptographic-handshake cost; simulation-style analysis | snippet |
| S2 | Brownfield et al. 2005 (IEEE); a 2023-era SBSeg paper | WSN; ESP32 testbed | MAC-level energy vulnerabilities; adaptive sleep control from local battery data, reported 51.2 % longer battery life under attack | Link-layer duty cycling, not handshake cost; paper details unverified | snippet |
| D1 | Stebila, Kuppusamy, Rangasamy, Boyd, Gonzalez Nieto. *Generic mechanisms for client puzzles / DoS-resistant key exchange* (CT-RSA 2011); Stebila & Ustaoglu (ACISP 2009, DoS-CMQV) | general | Generic combination of a protocol with a strong client puzzle; careful integration needed or the countermeasure fails | No energy measurement, no battery-powered peer, no learned decision | snippet |
| D2 | Springer chapter *Denial-of-Service in Quantum Based Key Exchange Over Classical Network Protocols* (authors not captured) | not stated | Argues exploitable DoS risks from negotiable fallback and authentication ordering in hybrid key exchange | Authors and scope unverified | snippet |
| I1 | IETF draft-ietf-ipsecme-ddos-protection (IKEv2 responder DoS) | IPsec | Cookies and client puzzles for IKEv2 responders | Internet scale, not a battery device on a broadcast channel | snippet |
| A1 | Stajano & Anderson. *The Resurrecting Duckling* (Security Protocols Workshop, 1999) | conceptual | Origin of "battery exhaustion"/"sleep deprivation torture" as a threat to small devices | Concept only | **memory** (search for it failed: verify) |
| E1 | Espressif developer blog, *Post-Quantum Cryptography on ESP32* (esp-pqc component), Oct 2026 | Espressif SoCs | Component with ML-KEM and ML-DSA; ML-DSA-65 verification about 44 ms in software; about 78 ms extra at boot (chip not confirmed) | Vendor blog; verification and boot, not energy or attack | snippet |
| M1 | Others from the searches, not yet opened: arXiv 2603.19340 (ML-KEM/ML-DSA on RP2040 Cortex-M0+: latency, rejection-sampling variance, memory); arXiv 2505.16614 (energy framework for PQ key generation on embedded devices); arXiv 2603.10274 / Sensors 26(9):2737 (PQ entropy as a service; DTLS 1.3 ML-KEM-512 handshake 313 ms on ESP32 as reported by a search summary); arXiv 2607.03988 (energy-aware PQ-TLS on embedded UE over 5G); arXiv 2506.19943 (quantum-resistant DNS, resource-exhaustion note) | various | various | open each before citing | snippet |

## 3. Reading of the gaps (for Section 11)

1. **PQC energy on microcontrollers is being measured, but for benign use.** G1, G2 and P1 all characterise cost when
   the device wants the operation. None characterises cost when an adversary chooses when the operation happens.
2. **Handshake exhaustion with PQC is being studied at the server** (L1: CPU, an AWS testbed), and for classical
   constrained peers (H1: puzzles). We found no measurement of the **battery** cost of a forged post-quantum
   handshake request on a microcontroller.
3. **Battery-exhaustion defences are link-layer** (S1, S2: sleep scheduling, MAC design) or **classical-crypto
   puzzles/cookies** (H1, D1, I1). We found none that combine a first-fragment decision, a joule budget and a bound
   independent of the classifier.
4. **A cookie on a broadcast medium** is a known weakness of the genre; our contribution is measuring it (ECHO
   attacker) and bounding it with the budget, not claiming it.
5. **Learned admission in front of a handshake:** a targeted search found only ML-based IoT DoS access-control
   surveys (an MLP suspicion factor; machine-learning detectors that shut the radio down) and nothing that scores a
   handshake request before public-key work and measures the energy of doing so. This is absence of evidence from
   one search round, not proof.

## 4. What we may and may not claim

- **May say:** "To our knowledge, and from the searches in `related_work.md` (date, venues), we found no prior
  measurement of the energy a forged or abusive post-quantum handshake costs a battery-powered microcontroller, and
  no defence that bounds it with a joule budget."
- **May not say:** "first", "novel" or "no prior work" without the full systematic pass below, and without locating
  Hristozov et al. and reading G2 and L1 in full.
- Gillot G2 already reports ESP32 PQC handshake energy for benign TLS, so **C1 alone is not novel**: the novelty is
  the attacker-driven cost, the ratio (C2) and the bound (C3).
- Do not quote the numbers in this file's snippet rows in the paper; re-read the source.

## 5. Search log (for the methods note)

All on 2026-10-24 through a web search tool, not the venue databases. **This is a first pass, not the systematic
search WORK_SPLIT asks for.**

| Query theme | Result |
|---|---|
| Gillot 2026 PQC energy MCU ESP32 | G1, G2, E1 found |
| ESP32-C6 PLOS ONE 2026 PQC | P1 found and opened |
| Lee 2026 arXiv PQ handshake DoS energy IoT | L1 found and opened |
| Hristozov (four variants) | nothing |
| Battery exhaustion / sleep deprivation defences | S1, S2 and generic WSN material |
| Client puzzles / cookies, IoT | D1, I1, H1 and a patent |
| Learned admission control before a handshake | no direct match |
| Stajano & Anderson | search failed (returned unrelated pages) |

## 6. Still to do for a proper S4

1. Get Hristozov et al.'s title from the team; read it.
2. Read G2, G1, P1, L1 and H1 in full; replace snippet rows with checked facts (platform, instrument, sample size,
   what they say about attackers).
3. Repeat the search in IEEE Xplore, ACM DL, IACR ePrint, Google Scholar and arXiv with the exact strings
   (record query, date, hit count, inclusion rule). Topics: PQC energy on microcontrollers; PQC handshake DoS;
   battery-exhaustion defences; client puzzles/cookies on broadcast radio; learned admission control; ESP-NOW
   security; token-bucket energy budgets.
4. Look for energy-denial work on LoRaWAN/BLE/Zigbee join procedures (the same shape: an unauthenticated request
   that triggers expensive work).
5. Citation keys: add a `references.bib` once the venue (and so the format) is chosen.
