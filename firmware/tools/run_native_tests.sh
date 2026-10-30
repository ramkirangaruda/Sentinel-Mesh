#!/usr/bin/env bash
# Builds and runs the host-side sentinel_proto unit tests with a plain g++
# invocation (no PlatformIO needed). Use `pio test -e native` instead once
# PlatformIO is installed on your machine.
set -euo pipefail
cd "$(dirname "$0")/.."

OUT=/tmp/sentinel_tests
g++ -std=gnu++17 -Wall -Wextra -Ilib/sentinel_proto/include \
    test/test_native/test_main.cpp lib/sentinel_proto/src/*.cpp \
    -o "$OUT"
"$OUT"

# attacker_pacer.h (src/attacker/, paper task S5 / E7): separate binary, since it lives outside
# sentinel_proto and only needs a handful of its sources (not msg_io/fragment/mesh_transport, which
# pull in Arduino.h).
OUT_ATTACKER=/tmp/sentinel_attacker_tests
g++ -std=gnu++17 -Wall -Wextra -Ilib/sentinel_proto/include -Isrc/attacker \
    test/test_attacker/test_main.cpp lib/sentinel_proto/src/link_window.cpp \
    lib/sentinel_proto/src/energygate.cpp lib/sentinel_proto/src/energy_budget.cpp \
    lib/sentinel_proto/src/gate_policy.cpp \
    -o "$OUT_ATTACKER"
"$OUT_ATTACKER"
