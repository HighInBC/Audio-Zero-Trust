#include "test_azt_registry.h"

#include <mbedtls/base64.h>

#include <array>
#include <vector>

#include "azt_crypto.h"

namespace azt_test {
namespace {

bool b64_decode_to_vec(const String& in, std::vector<uint8_t>& out) {
  out.assign(in.length() + 4, 0);
  size_t olen = 0;
  if (mbedtls_base64_decode(out.data(), out.size(), &olen,
                            reinterpret_cast<const unsigned char*>(in.c_str()),
                            in.length()) != 0) {
    return false;
  }
  out.resize(olen);
  return true;
}

bool test_hex_lower(Context&) {
  const uint8_t v[] = {0x00, 0x0f, 0x10, 0xab, 0xff};
  return azt::hex_lower(v, sizeof(v)) == "000f10abff";
}

bool test_hex_lower_empty(Context&) {
  return azt::hex_lower(reinterpret_cast<const uint8_t*>(""), 0) == "";
}

bool test_append_be(Context&) {
  std::vector<uint8_t> out;
  azt::append_u16_be(out, 0x1234);
  azt::append_u32_be(out, 0x89ABCDEFu);
  const std::array<uint8_t, 6> exp = {0x12, 0x34, 0x89, 0xAB, 0xCD, 0xEF};
  return out.size() == exp.size() && memcmp(out.data(), exp.data(), exp.size()) == 0;
}

bool test_append_be_multiple(Context&) {
  std::vector<uint8_t> out;
  for (uint16_t i = 0; i < 4; ++i) azt::append_u16_be(out, static_cast<uint16_t>(0x1000 + i));
  return out.size() == 8 && out[0] == 0x10 && out[1] == 0x00 && out[6] == 0x10 && out[7] == 0x03;
}

bool test_sha256_known(Context&) {
  const char* s = "abc";
  uint8_t h[32];
  if (!azt::sha256_bytes(reinterpret_cast<const uint8_t*>(s), 3, h)) return false;
  return azt::hex_lower(h, sizeof(h)) ==
         "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
}

bool test_sha256_empty(Context&) {
  uint8_t h[32];
  if (!azt::sha256_bytes(reinterpret_cast<const uint8_t*>(""), 0, h)) return false;
  return azt::hex_lower(h, sizeof(h)) ==
         "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
}

bool test_b64_small(Context&) {
  const uint8_t d[] = {1, 2, 3, 4, 5};
  String enc = azt::b64(d, sizeof(d));
  std::vector<uint8_t> dec;
  if (!b64_decode_to_vec(enc, dec)) return false;
  return dec.size() == sizeof(d) && memcmp(dec.data(), d, sizeof(d)) == 0;
}

bool test_b64_empty(Context&) {
  return azt::b64(nullptr, 0) == "";
}

bool test_b64_random_roundtrip(Context&) {
  uint8_t d[257];
  for (size_t i = 0; i < sizeof(d); ++i) d[i] = static_cast<uint8_t>(i & 0xFF);
  String enc = azt::b64(d, sizeof(d));
  std::vector<uint8_t> dec;
  if (!b64_decode_to_vec(enc, dec)) return false;
  return dec.size() == sizeof(d) && memcmp(dec.data(), d, sizeof(d)) == 0;
}

bool test_aes256_gcm_empty_vector(Context&) {
  uint8_t key[32] = {0};
  uint8_t nonce[12] = {0};
  const uint8_t pt[1] = {0x00};
  std::vector<uint8_t> ct;
  uint8_t tag[16] = {0};
  if (!azt::aes256_gcm_encrypt(key, nonce, pt, sizeof(pt), ct, tag)) return false;
  return ct.size() == 1 && ct[0] == 0xce &&
         azt::hex_lower(tag, sizeof(tag)) == "33ae4b7da7279a657bb29076a094d43e";
}

bool test_aes256_gcm_repeatability(Context&) {
  uint8_t key[32] = {0};
  uint8_t nonce[12] = {0};
  const uint8_t pt[3] = {0x01, 0x02, 0x03};
  std::vector<uint8_t> ct1, ct2;
  uint8_t t1[16] = {0}, t2[16] = {0};
  if (!azt::aes256_gcm_encrypt(key, nonce, pt, sizeof(pt), ct1, t1)) return false;
  if (!azt::aes256_gcm_encrypt(key, nonce, pt, sizeof(pt), ct2, t2)) return false;
  return ct1 == ct2 && memcmp(t1, t2, sizeof(t1)) == 0;
}

bool test_compute_pubkey_invalid(Context&) {
  String fp;
  return !azt::compute_pubkey_spki_sha256_hex("not a pem", fp);
}

bool test_compute_pubkey_valid(Context& ctx) {
  if (!ctx.pubkey_pem || ctx.pubkey_pem->length() < 64) return false;
  String fp;
  return azt::compute_pubkey_spki_sha256_hex(*ctx.pubkey_pem, fp) && fp.length() == 64;
}

bool test_rsa_encrypt_invalid_pub(Context&) {
  const uint8_t bad[] = {'b', 'a', 'd'};
  const uint8_t in[] = {1, 2, 3, 4};
  std::vector<uint8_t> out;
  return !azt::rsa_oaep_sha256_encrypt_pub(bad, sizeof(bad), in, sizeof(in), out);
}

bool test_rsa_encrypt_valid_pub_sane_len(Context& ctx) {
  if (!ctx.pubkey_pem || ctx.pubkey_pem->length() < 64) return false;
  const uint8_t in[32] = {0};
  std::vector<uint8_t> out;
  std::vector<uint8_t> pub(reinterpret_cast<const uint8_t*>(ctx.pubkey_pem->c_str()),
                           reinterpret_cast<const uint8_t*>(ctx.pubkey_pem->c_str()) + ctx.pubkey_pem->length() + 1);
  if (!azt::rsa_oaep_sha256_encrypt_pub(pub.data(), pub.size(), in, sizeof(in), out)) return false;
  return out.size() == 256;
}

bool test_pubkey_fingerprint_deterministic(Context& ctx) {
  if (!ctx.pubkey_pem || ctx.pubkey_pem->length() < 64) return false;
  String a, b;
  if (!azt::compute_pubkey_spki_sha256_hex(*ctx.pubkey_pem, a)) return false;
  if (!azt::compute_pubkey_spki_sha256_hex(*ctx.pubkey_pem, b)) return false;
  return a == b && a.length() == 64;
}

}  // namespace

void register_test_azt_crypto(Registry& out) {
  out.push_back({"HEX_LOWER", test_hex_lower, "hex conversion mismatch"});
  out.push_back({"HEX_LOWER_EMPTY", test_hex_lower_empty, "hex empty conversion mismatch"});
  out.push_back({"APPEND_BE", test_append_be, "big-endian append mismatch"});
  out.push_back({"APPEND_BE_MULTIPLE", test_append_be_multiple, "big-endian multi append mismatch"});
  out.push_back({"SHA256_KNOWN", test_sha256_known, "sha256 known vector mismatch"});
  out.push_back({"SHA256_EMPTY", test_sha256_empty, "sha256 empty vector mismatch"});
  out.push_back({"B64_SMALL", test_b64_small, "b64 roundtrip mismatch"});
  out.push_back({"B64_EMPTY", test_b64_empty, "b64 empty handling mismatch"});
  out.push_back({"B64_RANDOM_ROUNDTRIP", test_b64_random_roundtrip, "b64 random roundtrip mismatch"});
  out.push_back({"AES256_GCM_EMPTY_VECTOR", test_aes256_gcm_empty_vector, "aes256-gcm empty vector mismatch"});
  out.push_back({"AES256_GCM_REPEATABILITY", test_aes256_gcm_repeatability, "aes256-gcm repeatability mismatch"});
  out.push_back({"COMPUTE_PUBKEY_INVALID", test_compute_pubkey_invalid, "invalid pubkey should fail"});
  out.push_back({"COMPUTE_PUBKEY_VALID", test_compute_pubkey_valid, "valid pubkey should pass"});
  out.push_back({"RSA_ENCRYPT_INVALID_PUB", test_rsa_encrypt_invalid_pub, "invalid rsa pubkey should fail"});
  out.push_back({"RSA_ENCRYPT_VALID_PUB_SANE_LEN", test_rsa_encrypt_valid_pub_sane_len, "valid rsa pubkey encryption sanity failed"});
  out.push_back({"PUBKEY_FINGERPRINT_DETERMINISTIC", test_pubkey_fingerprint_deterministic, "fingerprint determinism mismatch"});
}

}  // namespace azt_test
