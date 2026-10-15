#ifdef ARDUINO

#include "common/aead.h"
#include <mbedtls/gcm.h>
#include <cstring>

namespace sentinel::aead {

void build_nonce(uint8_t sender, uint16_t epoch, uint32_t seq, uint8_t out[GCM_NONCE_LEN]) {
    memset(out, 0, GCM_NONCE_LEN);
    out[0] = sender;
    out[1] = static_cast<uint8_t>(epoch >> 8);
    out[2] = static_cast<uint8_t>(epoch);
    out[3] = static_cast<uint8_t>(seq >> 24);
    out[4] = static_cast<uint8_t>(seq >> 16);
    out[5] = static_cast<uint8_t>(seq >> 8);
    out[6] = static_cast<uint8_t>(seq);
    // bytes 7..11 stay zero -- padding, per packet.h's documented scheme.
}

bool encrypt(const uint8_t key[32], const uint8_t nonce[GCM_NONCE_LEN],
             const uint8_t* aad, size_t aad_len,
             const uint8_t* plaintext, size_t plaintext_len,
             std::vector<uint8_t>& out) {
    mbedtls_gcm_context ctx;
    mbedtls_gcm_init(&ctx);
    if (mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, key, 256) != 0) {
        mbedtls_gcm_free(&ctx);
        return false;
    }

    out.resize(plaintext_len + GCM_TAG_LEN);
    uint8_t tag[GCM_TAG_LEN];
    int rc = mbedtls_gcm_crypt_and_tag(&ctx, MBEDTLS_GCM_ENCRYPT, plaintext_len,
                                        nonce, GCM_NONCE_LEN, aad, aad_len,
                                        plaintext, out.data(), GCM_TAG_LEN, tag);
    mbedtls_gcm_free(&ctx);
    if (rc != 0) return false;
    memcpy(out.data() + plaintext_len, tag, GCM_TAG_LEN);
    return true;
}

bool decrypt(const uint8_t key[32], const uint8_t nonce[GCM_NONCE_LEN],
             const uint8_t* aad, size_t aad_len,
             const uint8_t* in, size_t in_len,
             std::vector<uint8_t>& out) {
    if (in_len < GCM_TAG_LEN) return false;
    size_t ct_len = in_len - GCM_TAG_LEN;

    mbedtls_gcm_context ctx;
    mbedtls_gcm_init(&ctx);
    if (mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, key, 256) != 0) {
        mbedtls_gcm_free(&ctx);
        return false;
    }

    out.resize(ct_len);
    int rc = mbedtls_gcm_auth_decrypt(&ctx, ct_len, nonce, GCM_NONCE_LEN, aad, aad_len,
                                       in + ct_len, GCM_TAG_LEN, in, out.data());
    mbedtls_gcm_free(&ctx);
    return rc == 0;
}

} // namespace sentinel::aead

#endif // ARDUINO
