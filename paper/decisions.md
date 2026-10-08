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
