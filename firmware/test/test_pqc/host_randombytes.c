/* Host-only entropy source for the PQClean tests (the ESP32 build uses
 * randombytes_esp32.c). */
#include <stdio.h>
#include "randombytes.h"
int randombytes(uint8_t *output, size_t n) {
    FILE *f = fopen("/dev/urandom", "rb");
    if (!f) return -1;
    size_t got = fread(output, 1, n, f);
    fclose(f);
    return got == n ? 0 : -1;
}
