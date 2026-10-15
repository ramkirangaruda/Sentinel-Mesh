# Phase 1: design decisions (team fills the "Decision" column)

Recommended answers are from the execution guide. Overrule any of them, but write why.

| # | Decision | Recommended | **Decision (team)** | Reason if different |
|---|---|---|---|---|
| 1 | KEM / signature pairing | ML-KEM-512+ML-DSA-44 main; also 768+65 and 1024+87 | | |
| 2 | Adaptive ML-KEM level by battery | Drop for the paper (one fixed level per run) | | |
| 3 | Cookie challenge | Keep as a baseline; it only stops blind/off-path spoofers (ESP-NOW is broadcast) | | |
| 4 | Jamming | Out of scope (continuous, detectable, doesn't drain the battery) | | |
| 5 | HMAC-PSK fallback | Drop from the paper; keep the code if wanted | | |
| 6 | Check order on an incoming HELLO | header sanity, replay/freshness, cookie, EnergyGate+budget, reassembly, ML-DSA verify | | |
| 7 | Source of truth for numbers | `paper/` folder; README updated from it | | |

Also decide: key provisioning (flash each node's ML-DSA public key into F1 at build time), owner per phase, first-choice and fallback venue.

> Note found while setting up: an unmerged branch `v4-esp-now-and-handshake` already has ESP-NOW transport and an **HMAC-PSK** handshake with AES-256-GCM (not PQC). Decide whether to merge it as the base for Phase 6.

---

# Phase 6: what was actually built (branch `paper/phase6-handshake`, 2026-10-12)

These are the choices made while writing the handshake firmware. Each one changes what the paper can claim, so each is stated here.

| # | Topic | What was built | Consequence for the paper |
|---|---|---|---|
| 1 | Parameter set | KEM and signature paired by NIST level, fixed at compile time: `SENTINEL_PQC_LEVEL=1` (ML-KEM-512 + ML-DSA-44) or `3` (ML-KEM-768 + ML-DSA-65). No runtime level selection. Level 5 is not offered because ML-DSA-87 signing does not fit (E1). | Decision 1 and 2 above are settled: two parameter sets, no adaptive level. The brief's adaptive-level claim is dropped. |
| 2 | Protocol | Signed-KEM, 3 messages, `HELLO` (cookie, nonce, ephemeral ML-KEM key, ML-DSA signature) / `RESPONSE` (nonce echo, nonce, KEM ciphertext, ML-DSA signature) / `CONFIRM` (nonce, key-confirmation tag). Transcript hashes bind both ids and all fields; SHAKE256 is the KDF and MAC. Session keys: one per direction, used with AES-256-GCM, header as AAD. See `lib/sentinel_pqc/include/sentinel_pqc/pqc_handshake.h`. | It is a plain, unverified protocol. Do not call it formally secure. Host-tested against the real PQClean code (`tools/run_pqc_tests.sh`): honest run, forged signature, wrong key, tampered fields, wrong identity, tampered RESPONSE/CONFIRM, replayed CONFIRM, fragmentation round trip. |
| 3 | Message sizes | Level 1: HELLO 3244 B (14 frames), RESPONSE 3220 B (14 frames). Level 3: HELLO 4517 B (20 frames), RESPONSE 4429 B (19 frames). CONFIRM 48 B (1 frame). ESP-NOW v1, 235 B payload per frame. | Radio airtime and TX/RX energy are part of C1; the frame counts are measured, not estimated. |
| 4 | Roles | Gateway is always the initiator, field-1 always the responder. A real field node never sends HELLO. | A HELLO claiming field-1's id is an impersonation by construction, and the gateway never hears its own frames, so a HELLO claiming the gateway's id is a forgery too. |
| 5 | Cookie | CHALLENGE (new message type 0x09) carries the 8-byte cookie; the initiator echoes it in the same signed HELLO (the cookie is outside the signed transcript, so no second signature). | ESP-NOW is a shared broadcast medium: an attacker in range hears every CHALLENGE and can echo the cookie (`ECHO on` on the attacker). The cookie only stops blind spoofers. It is a baseline, not a defence against a listening attacker. |
| 6 | Where EnergyGate decides | On the first fragment of a HELLO, before reassembly and before any public-key work. SPEND admits the fragment set; CHALLENGE sends a cookie; DROP is silence and the remaining fragments of that set are ignored. | Saves the reception of the rest of the message only as far as the radio can be told to ignore it: the radio still receives and the CPU still wakes for every frame. That residual cost is measured, not assumed away. |
| 7 | Threat model: what the attacker is | Three attackers, not one. `FLOOD`: forged HELLOs claiming the gateway's id with random signature bytes (costs field-1 reception plus, if admitted, one failing ML-DSA verification). `INSIDER`: HELLOs validly signed with an ENROLLED attacker key (a compromised or hostile enrolled peer); each admitted HELLO forces verify + encapsulate + sign + 19 frames of RESPONSE. `SLOW_DRIP`: INSIDER at about one per minute. A sender with no enrolled key is dropped for free by an allow-list check before the gate is consulted. | State this explicitly. Without enrollment the allow-list already stops unknown senders; EnergyGate matters for spoofed-identity and enrolled-but-hostile senders. |
| 8 | One handshake at a time | The post-quantum work runs in one dedicated task with a large stack; while it is busy, further admissions are refused and counted as `busy_drop`, and in GATE mode their joules are refunded. | Bounds the victim's crypto work and RAM, and caps how much a flood can cost per second. It also means a flood can make the legitimate gateway's handshake fail (measured as legit connect %). |
| 9 | Replay guard on HELLO | The highest (epoch, seq) per sender that has actually VERIFIED. Unverified HELLOs never advance it. | An unauthenticated flood with huge sequence numbers cannot lock the real gateway out. Captured-and-replayed HELLOs are rejected before the gate at no cost. |
| 10 | Features | A rolling 5-second window (five 1-second buckets, `sentinel_proto/link_window.h`). `hs_per_s` counts HELLO attempts, not fragments. `loss_pct` is frames dropped at the receive queue / (received + dropped) because the original sequence-gap definition was never populated on hardware. `frag_complete_pct` counts admitted sets only (counting dropped sets would make the gate lock itself into dropping). RSSI comes from a promiscuous-mode sniffer keyed on source MAC, because the Arduino-ESP32 2.x ESP-NOW callback has no RSSI; if no sample exists the frame is flagged and the placeholder is -50 (`rssi_missing` is logged). | The shipped EnergyGate model was trained on SIMULATED traces with slightly different feature definitions. Until it is retrained on traces recorded from these boards (Phase 8 onwards), its behaviour on real traffic is NOT a result. |
| 11 | Battery | `-DSENTINEL_NO_BATTERY` fixes `battery_pct` at 100. SIMULATED. | `battery_pct` carries no information in E5 until a real cell is added; do not claim the model uses it. |
| 12 | Unauthenticated control channel | `GATE_REPORT`, `CONTROL` and `CHALLENGE` are plain. The decisions and defence mode are reported over the same radio the attacker shares. | Lab rig only. Report it as a limitation. The report is rate-limited (default 200 ms) because it is radio traffic on the measured battery; the exact decision counts travel in the encrypted DATA stats payload every 3 s. |
| 13 | Keys | Demo ML-DSA key pairs generated by `tools/gen_demo_keys.sh`, committed, compiled into every image. | Not key management. Say so. |
| 14 | Teammate branch | `origin/v4-esp-now-and-handshake` (HMAC-PSK handshake) was NOT merged. Its ESP-NOW transport and AES-GCM wrapper were reused (`aead.*` as is, `mesh_transport.*` rewritten around a receive queue, send pacing and an RSSI sniffer). Its HMAC-PSK handshake is replaced, not kept. | Decision 5 above (drop the HMAC-PSK fallback) is settled. Merging that branch later will conflict on `field_node/main.cpp`, `gateway/main.cpp` and `attacker/main.cpp`. |

| 15 | Replay guard (revises #9) | Per sender, a ring of 8 verified epochs, each with its highest verified seq. A HELLO is a replay only if its epoch is in the ring and seq <= the recorded one. A new epoch is never "older". | The first version compared epochs numerically; a rebooted gateway with a lower random epoch was locked out until F power-cycled (bench log `bench_gateway_after_reboot_2026-10-12.log`). Limitation: a captured signed HELLO whose epoch has aged out of the ring can be replayed once and costs one full handshake. Report it. |

| 16 | Attacker boot mode | `env:attacker_flood`, `attacker_insider`, `attacker_slowdrip` start attacking at power-up (`-DSENTINEL_ATTACKER_BOOT_MODE`, optional `-DSENTINEL_ATTACKER_RATE_HZ`). `env:attacker` still boots OFF. | The attack mode is not persisted. A charger- or INA219-powered attacker (E5, and C2's attacker energy) has no serial link, so it needs a build-time mode. Every run must record which attacker env and rate were used. |

| 17 | Gate policy v2 (revises the GATE rules) | In GATE mode a low score is no longer dropped: it is CHALLENGED (charged `challenge_cost_j`, placeholder 0.0005 J) and a returned cookie admits the sender (still charged a full handshake from the joule budget). DROP remains for an exhausted budget. `-DSENTINEL_GATE_V1` (`env:field_node_bench_gatev1`) restores v1 for the ablation. | Motivation, measured: the first gate flood run (`bench_gateway_2026-10-14_flood_defence_gate_full.log`) dropped 589 forged HELLOs but also all 10 legitimate handshakes, because forged and real HELLOs claim the same sender id and the window features cannot tell them apart. That run IS the v1 result: report it next to v2. Limitations to state: the challenge is unauthenticated and a listening attacker can echo the cookie (the budget then bounds the damage); the 0.0005 J challenge cost is a placeholder until measured on the rig; the scoring model is still trained on SIMULATED traces. |

## Open risks in this firmware (nothing here has run on a board yet)

1. **Heap.** The crypto task reserves its stack (90 112 B at level 3, 49 152 B at level 1) before Wi-Fi starts. If ML-DSA-65 plus Wi-Fi plus the buffers do not fit, the boot log says so (`crypto_task: cannot allocate` or `FAILED`). The real stack need is read off `stack_free_min` in the logs and the reservation lowered accordingly.
2. **RSSI sniffer.** The promiscuous-mode trick has not been run on these boards. If `rssi_sniffer=OFF` or `rssi_missing` is large in the stats lines, RSSI features are the placeholder.
3. **Signing time under Wi-Fi.** E1 timings were taken with the radio off. Signing time with Wi-Fi running (and the radio sharing the CPU) will differ; use these runs, not E1, for any handshake-level number.

## Decision: integration of PRs #9, #10, #11 into master (2026-10-15)
- #11 (paper/phase6-handshake): merged whole.
- #9 (MailGuard revert): merged; one conflict in `ml/mailguard.py` resolved keeping master's score-only change and `verdict()` bands, dropping the padding helpers. ML owner (Chaitanya) should review. `ml/models/mailguard.joblib` restored to the pre-#5 blob.
- #10 (hardware bring-up): only the hardware fixes were taken: 16x2 I2C LCD (`LiquidCrystal_I2C`, addr 0x27), direct-I2C MPU6050 (clone fails Adafruit WHO_AM_I), blue "secure" LED. Its HMAC handshake (`handshake.*`, `psk.h`) is superseded by the signed ML-KEM handshake and was NOT included; `.vscode` files not included.
- NOT build-verified for ESP32 in the cloud sandbox (platform download blocked). Host tests: 305 native + PQC pass; host syntax checks of field_node/gateway pass with stubs. Someone must run `pio run` for every env, and confirm the LCD address (0x27 vs 0x3F) on the boards, before relying on master.
- Two ML test files (`test_fileguard_redteam.py`, `test_fileguard_shap.py`) need `pefile`/`lightgbm` and were not run here; the other 15 pass.
