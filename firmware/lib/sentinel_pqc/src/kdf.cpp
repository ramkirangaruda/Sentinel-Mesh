#include "sentinel_pqc/kdf.h"
#include <cstring>
extern "C" {
#include "fips202.h"
}

namespace sentinel::pqc {

static void absorb_be(shake256incctx* st, uint32_t v, int bytes) {
    uint8_t b[4];
    for (int i = 0; i < bytes; i++) b[i] = static_cast<uint8_t>(v >> (8 * (bytes - 1 - i)));
    shake256_inc_absorb(st, b, static_cast<size_t>(bytes));
}

void xof(uint8_t* out, size_t out_len, const char* label, const Part* parts, size_t n_parts) {
    shake256incctx st;
    shake256_inc_init(&st);
    size_t ll = strlen(label);
    absorb_be(&st, static_cast<uint32_t>(ll), 2);
    shake256_inc_absorb(&st, reinterpret_cast<const uint8_t*>(label), ll);
    for (size_t i = 0; i < n_parts; i++) {
        absorb_be(&st, static_cast<uint32_t>(parts[i].n), 4);
        if (parts[i].n) shake256_inc_absorb(&st, parts[i].p, parts[i].n);
    }
    shake256_inc_finalize(&st);
    shake256_inc_squeeze(out, out_len, &st);
    shake256_inc_ctx_release(&st);
}

bool ct_equal(const uint8_t* a, const uint8_t* b, size_t n) {
    uint8_t d = 0;
    for (size_t i = 0; i < n; i++) d |= static_cast<uint8_t>(a[i] ^ b[i]);
    return d == 0;
}

} // namespace sentinel::pqc
