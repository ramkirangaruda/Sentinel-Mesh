# Vendored PQClean (ML-KEM and ML-DSA)

Portable reference ("clean") C implementations, copied unmodified from
https://github.com/PQClean/PQClean at commit
`0586a824fc0d49df0b6b6e9179d8d15d06d0974f` (fetched 2026-10-08).

| Folder under `src/pqclean/` | Source in PQClean | Standard |
|---|---|---|
| `ml-kem-512`, `ml-kem-768`, `ml-kem-1024` | `crypto_kem/ml-kem-*/clean` | FIPS 203 (final) |
| `ml-dsa-44`, `ml-dsa-65`, `ml-dsa-87` | `crypto_sign/ml-dsa-*/clean` | FIPS 204 (final) |
| `common` | `common/fips202.{c,h}`, `compat.h`, `randombytes.h` | SHA-3 / SHAKE |

**Not copied:** PQClean's `randombytes.c` (uses desktop OS calls). Replaced by
`common/randombytes_esp32.c`, which calls the ESP32 hardware RNG
(`esp_fill_random`). With the radio off, enable `bootloader_random` first.

Licence: public domain / CC0 (see `LICENSE.PQClean` and the per-folder LICENSE files).

## Caveats for the paper
- PQClean is being archived from July 2026; this is a frozen copy. State the
  commit above in the Methods section.
- This is the **portable reference code, not optimized for Xtensa**. Absolute
  speed and energy will be worse than an assembly-optimized build. Say so as a
  limitation. Relative results (attacker vs victim cost) are unaffected.
- ML-DSA signing time varies by design (rejection sampling). Report distributions.

## Updating
Re-copy the six algorithm folders and `common` files from a PQClean checkout,
update the commit above and `library.json`, rebuild with `pio run -e benchmark`.
