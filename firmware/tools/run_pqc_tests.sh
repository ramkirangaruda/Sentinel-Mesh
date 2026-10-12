#!/usr/bin/env bash
# Host test of the PQC handshake against the real PQClean sources (no ESP32).
set -euo pipefail
cd "$(dirname "$0")/.."
P=lib/pqclean/src/pqclean
for LEVEL in 1 3; do
  if [ "$LEVEL" = 1 ]; then KEM=ml-kem-512; SIG=ml-dsa-44; else KEM=ml-kem-768; SIG=ml-dsa-65; fi
  OUT=/tmp/sentinel_pqc_test_L$LEVEL
  B=$(mktemp -d)
  # ML-KEM and ML-DSA share file names (poly.c, ntt.c ...), so build each into its own dir.
  for D in $KEM $SIG; do
    mkdir -p "$B/$D"
    for F in $P/$D/*.c; do gcc -O2 -c -I$P/common -Ilib/pqclean/src "$F" -o "$B/$D/$(basename "$F" .c).o"; done
  done
  gcc -O2 -c -I$P/common $P/common/fips202.c -o "$B/fips202.o"
  gcc -O2 -c -I$P/common test/test_pqc/host_randombytes.c -o "$B/rb.o"
  g++ -std=gnu++17 -O2 -Wall -Wextra -DSENTINEL_PQC_LEVEL=$LEVEL -Ilib/sentinel_pqc/include -Ilib/pqclean/src -I$P/common \
      test/test_pqc/test_pqc.cpp lib/sentinel_pqc/src/*.cpp "$B"/*.o "$B"/$KEM/*.o "$B"/$SIG/*.o -o "$OUT"
  rm -rf "$B"
  "$OUT"
done
