/* ESP32 entropy source for PQClean (replaces PQClean's desktop randombytes.c).
 *
 * randombytes.h maps `randombytes` to `PQCLEAN_randombytes`, so defining
 * randombytes() here defines that symbol. esp_fill_random() is the ESP32
 * hardware RNG. It is cryptographically strong while Wi-Fi or Bluetooth is
 * active; with the radio off, call bootloader_random_enable() first (the
 * benchmark does this with -DSENTINEL_BENCH_TRUE_RANDOM_NO_RADIO).
 */
#include "randombytes.h"

#if defined(__has_include)
#  if __has_include(<esp_random.h>)
#    include <esp_random.h>
#  endif
#endif
#include <esp_system.h>

int randombytes(uint8_t *output, size_t n) {
    esp_fill_random(output, n);
    return 0;
}
