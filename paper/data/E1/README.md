# E1 — on-device PQC timing (radio off, 240 MHz, PQClean clean C, USB powered)
Raw captures: `board_<MAC>_runN_raw.txt` (terminal transcript incl. build/upload; benchmark CSV starts after `algo,op,us,...`).
Boards: see boards.csv (F,G,A,M). Raw logs in raw/. ML-DSA-87 sign does not fit (largest free heap block 110580 B -> 94196 B stack).
Caveats: heap_used_bytes is 0 (buffers are static); X25519/ECDSA baselines are mbedtls generic C, not an optimised Curve25519, so do not claim PQC beats classical from these.
Need >= 5 runs per board before any number goes in the paper.
