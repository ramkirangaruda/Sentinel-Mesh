#pragma once
// DEMO ML-DSA key pairs (public secret keys -- lab rig only, see decisions.md).
// Selected by the same SENTINEL_PQC_LEVEL the handshake uses.
#ifndef SENTINEL_PQC_LEVEL
#define SENTINEL_PQC_LEVEL 3
#endif
#if SENTINEL_PQC_LEVEL == 1
#  include "common/demo_keys_l1.h"
#else
#  include "common/demo_keys_l3.h"
#endif
