#!/usr/bin/env bash
# Regenerates src/common/demo_keys_l1.h and demo_keys_l3.h (DEMO ML-DSA key pairs).
# Only needed if you want fresh keys; the committed ones work as they are.
set -euo pipefail
cd "$(dirname "$0")/.."
P=lib/pqclean/src/pqclean
for LEVEL in 1 3; do
  if [ "$LEVEL" = 1 ]; then SIG=ml-dsa-44; KEM=ml-kem-512; else SIG=ml-dsa-65; KEM=ml-kem-768; fi
  B=$(mktemp -d)
  for D in $SIG; do mkdir -p "$B/$D"; for F in $P/$D/*.c; do gcc -O2 -c -I$P/common -Ilib/pqclean/src "$F" -o "$B/$D/$(basename "$F" .c).o"; done; done
  gcc -O2 -c -I$P/common $P/common/fips202.c -o "$B/fips202.o"
  gcc -O2 -c -I$P/common test/test_pqc/host_randombytes.c -o "$B/rb.o"
  # the KEM headers are only included for the size constants
  g++ -std=gnu++17 -O2 -DSENTINEL_PQC_LEVEL=$LEVEL -Ilib/sentinel_pqc/include -Ilib/pqclean/src -I$P/common \
      tools/gen_demo_keys.cpp "$B"/*.o "$B"/$SIG/*.o -o "$B/gen"
  "$B/gen" src/common/demo_keys_l$LEVEL.h
  rm -rf "$B"
done
echo "wrote src/common/demo_keys_l1.h and demo_keys_l3.h"
