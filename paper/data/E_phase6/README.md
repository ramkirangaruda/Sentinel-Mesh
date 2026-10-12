# Phase 6 bench logs

`bench_gateway_F_G_2026-10-12.log`: first run of the real handshake. Gateway (board G, `env:gateway`,
ML-KEM-768 + ML-DSA-65) and field node (board F, `env:field_node_bench`), no energy rig, boards ~adjacent.
Raw serial capture, ~2 min. Not a measurement: radio on, USB power, no marker.

What it shows: 10 handshakes, 0 failures, 0 challenges, 0 drops; session established in 360-530 ms;
gateway-side timings (keygen ~9 ms, verify ~27 ms, decaps ~12 ms, sign 52-174 ms, high variance);
crypto-task stack free minimum 9960 B of 90112; RSSI sniffer works (rssi_missing=0).

Known artefact: this run was recorded BEFORE a gateway fix. Every scheduled handshake was
immediately followed by a second one (the state machine read the stale next-start time before
consuming the result). Fixed in the commit after this file was added; do not count these as 2x
the intended rate.

`bench_gateway_after_reboot_2026-10-12.log`: gateway reflashed (9ccc095 build) while field node F kept
running its previous image state. Every handshake times out (`reason=timeout`, backoff 1 s to 15 s).
Cause: F's replay guard compared epochs numerically; the rebooted gateway drew a random epoch lower than
the one F had recorded, so F dropped every HELLO as a replay before the gate. Fixed by an exact-epoch
ring (decision 15). A failure that was a bug, kept here as a record, not a result.
