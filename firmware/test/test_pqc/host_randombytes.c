/* Host-only entropy source for the PQClean tests (the ESP32 build uses
 * randombytes_esp32.c). Windows (MinGW) has no /dev/urandom, so it uses
 * rand_s there; without this every handshake call fails with CRYPTO_ERROR. */
#ifdef _WIN32
#define _CRT_RAND_S
#include <stdlib.h>
#endif
#include <stdio.h>
#include "randombytes.h"
int randombytes(uint8_t *output, size_t n) {
#ifdef _WIN32
    for (size_t i = 0; i < n; i++) {
        unsigned int v;
        if (rand_s(&v) != 0) return -1;
        output[i] = (uint8_t)v;
    }
    return 0;
#else
    FILE *f = fopen("/dev/urandom", "rb");
    if (!f) return -1;
    size_t got = fread(output, 1, n, f);
    fclose(f);
    return got == n ? 0 : -1;
#endif
}
