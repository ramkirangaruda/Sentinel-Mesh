# E0 host test of the vendored PQClean code

Compiled with gcc (Linux x86-64, -O2) against `firmware/lib/pqclean/src`, using
`/dev/urandom` for randomness. This checks the *copy* is intact; it says nothing
about ESP32 speed, memory or energy.

Build: `gcc -O2 -I firmware/lib/pqclean/src -I firmware/lib/pqclean/src/pqclean/common hosttest.c $(find firmware/lib/pqclean/src/pqclean -name '*.c' ! -name randombytes_esp32.c) -o hosttest`

Result (2026-10-08), PQClean commit 0586a824fc0d49df0b6b6e9179d8d15d06d0974f:
```
ML-KEM-512 pk=800 ct=768 roundtrip=ok tampered_ct_differs=ok
ML-KEM-768 pk=1184 ct=1088 roundtrip=ok tampered_ct_differs=ok
ML-KEM-1024 pk=1568 ct=1568 roundtrip=ok tampered_ct_differs=ok
ML-DSA-44 pk=1312 sig=2420 roundtrip=ok forged_rejected=ok
ML-DSA-65 pk=1952 sig=3309 roundtrip=ok forged_rejected=ok
ML-DSA-87 pk=2592 sig=4627 roundtrip=ok forged_rejected=ok
ALL OK
```
Sizes match FIPS 203/204 (e.g. ML-DSA-44 signature 2,420 B; ML-KEM-1024 public key 1,568 B).
