#include "azt_crypto.h"

#include <esp_system.h>
#include <sodium.h>
#include <mbedtls/base64.h>
#include <mbedtls/gcm.h>
#include <mbedtls/md.h>
#include <mbedtls/pk.h>
#include <mbedtls/rsa.h>

namespace azt {

String b64(const uint8_t* data, size_t len) {
  if (!data || len == 0) return String("");
  size_t olen = 0;
  mbedtls_base64_encode(nullptr, 0, &olen, data, len);
  std::vector<uint8_t> out(olen + 1, 0);
  if (mbedtls_base64_encode(out.data(), out.size(), &olen, data, len) != 0) return String("");
  return String(reinterpret_cast<const char*>(out.data()));
}

bool b64_decode_vec(const String& in, std::vector<uint8_t>& out) {
  out.assign(in.length() + 8, 0);
  size_t olen = 0;
  if (mbedtls_base64_decode(out.data(), out.size(), &olen,
                            reinterpret_cast<const unsigned char*>(in.c_str()),
                            in.length()) != 0) {
    return false;
  }
  out.resize(olen);
  return true;
}

String hex_lower(const uint8_t* data, size_t len) {
  static const char* H = "0123456789abcdef";
  String s;
  s.reserve(len * 2);
  for (size_t i = 0; i < len; ++i) {
    uint8_t b = data[i];
    s += H[(b >> 4) & 0xF];
    s += H[b & 0xF];
  }
  return s;
}

void append_u16_be(std::vector<uint8_t>& out, uint16_t v) {
  out.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
  out.push_back(static_cast<uint8_t>(v & 0xFF));
}

void append_u32_be(std::vector<uint8_t>& out, uint32_t v) {
  out.push_back(static_cast<uint8_t>((v >> 24) & 0xFF));
  out.push_back(static_cast<uint8_t>((v >> 16) & 0xFF));
  out.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
  out.push_back(static_cast<uint8_t>(v & 0xFF));
}

static int rng_cb(void* /*ctx*/, unsigned char* out, size_t len) {
  esp_fill_random(out, len);
  return 0;
}

bool sha256_bytes(const uint8_t* msg, size_t msg_len, uint8_t out32[32]) {
  const mbedtls_md_info_t* md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
  if (!md) return false;
  mbedtls_md_context_t ctx;
  mbedtls_md_init(&ctx);
  bool ok = false;
  do {
    if (mbedtls_md_setup(&ctx, md, 0) != 0) break;
    if (mbedtls_md_starts(&ctx) != 0) break;
    if (mbedtls_md_update(&ctx, msg, msg_len) != 0) break;
    if (mbedtls_md_finish(&ctx, out32) != 0) break;
    ok = true;
  } while (0);
  mbedtls_md_free(&ctx);
  return ok;
}

bool compute_pubkey_spki_sha256_hex(const String& pub_pem, String& out_hex) {
  out_hex = "";
  mbedtls_pk_context pk;
  mbedtls_pk_init(&pk);
  bool ok = false;
  do {
    std::vector<uint8_t> pem(reinterpret_cast<const uint8_t*>(pub_pem.c_str()),
                             reinterpret_cast<const uint8_t*>(pub_pem.c_str()) + pub_pem.length() + 1);
    if (mbedtls_pk_parse_public_key(&pk, pem.data(), pem.size()) != 0) break;

    unsigned char der[2048];
    memset(der, 0, sizeof(der));
    int ret = mbedtls_pk_write_pubkey_der(&pk, der, sizeof(der));
    if (ret <= 0) break;
    size_t der_len = static_cast<size_t>(ret);
    const uint8_t* der_ptr = der + sizeof(der) - der_len;

    uint8_t h[32];
    if (!sha256_bytes(der_ptr, der_len, h)) break;
    out_hex = hex_lower(h, sizeof(h));
    ok = true;
  } while (0);
  mbedtls_pk_free(&pk);
  return ok;
}

bool rsa_oaep_sha256_encrypt_pub(const uint8_t* pub_pem,
                                 size_t pub_len,
                                 const uint8_t* in,
                                 size_t in_len,
                                 std::vector<uint8_t>& out) {
  out.clear();
  mbedtls_pk_context pk;
  mbedtls_pk_init(&pk);

  bool ok = false;
  do {
    if (mbedtls_pk_parse_public_key(&pk, pub_pem, pub_len) != 0) break;
    if (!mbedtls_pk_can_do(&pk, MBEDTLS_PK_RSA)) break;

#if defined(MBEDTLS_RSA_C)
    mbedtls_rsa_context* rsa = mbedtls_pk_rsa(pk);
    mbedtls_rsa_set_padding(rsa, MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA256);
#endif

    size_t olen = mbedtls_pk_get_len(&pk);
    out.assign(olen, 0);
    if (mbedtls_pk_encrypt(&pk, in, in_len, out.data(), &olen, out.size(), rng_cb, nullptr) != 0) break;
    out.resize(olen);
    ok = true;
  } while (0);

  mbedtls_pk_free(&pk);
  return ok;
}

bool verify_ed25519_signature_b64(const String& pub_b64,
                                  const std::vector<uint8_t>& payload,
                                  const String& sig_b64) {
  std::vector<uint8_t> pub;
  std::vector<uint8_t> sig;
  if (!b64_decode_vec(pub_b64, pub) || pub.size() != crypto_sign_ed25519_PUBLICKEYBYTES) return false;
  if (!b64_decode_vec(sig_b64, sig) || sig.size() != crypto_sign_ed25519_BYTES) return false;

  return crypto_sign_ed25519_verify_detached(sig.data(),
                                             payload.data(),
                                             payload.size(),
                                             pub.data()) == 0;
}

bool aes256_gcm_encrypt(const uint8_t* key32,
                        const uint8_t* nonce12,
                        const uint8_t* plaintext,
                        size_t plaintext_len,
                        std::vector<uint8_t>& ciphertext,
                        uint8_t tag16[16]) {
  mbedtls_gcm_context gcm;
  mbedtls_gcm_init(&gcm);

  bool ok = false;
  ciphertext.assign(plaintext_len, 0);

  do {
    if (mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key32, 256) != 0) break;
    if (mbedtls_gcm_crypt_and_tag(&gcm,
                                  MBEDTLS_GCM_ENCRYPT,
                                  plaintext_len,
                                  nonce12,
                                  12,
                                  nullptr,
                                  0,
                                  plaintext,
                                  ciphertext.data(),
                                  16,
                                  tag16) != 0) break;
    ok = true;
  } while (0);

  mbedtls_gcm_free(&gcm);
  return ok;
}

}  // namespace azt
