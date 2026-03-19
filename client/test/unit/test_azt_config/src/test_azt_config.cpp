#include "test_azt_registry.h"

#include <mbedtls/md.h>
#include <mbedtls/pk.h>
#include <mbedtls/rsa.h>
#include <esp_system.h>
#include <Preferences.h>

#include <vector>

#include "azt_config.h"
#include "azt_crypto.h"

namespace azt_test {
namespace {

// Throwaway test-only keypair for local unit tests. Never use in production.
static const char* kTestAdminPrivateKeyPem = R"PEM(-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEAzAedMnuIkQu+K2MfuHISbV5bsWTwAnKHjU4Hu+S+nKlfKqqc
ud1SMj7Hs/8qWwQgOtZqGEW5RL4hlYi8UpKVLeJD1J7JG5Wv4ofc4vMcetcvX+6D
c1Z7Kbo1hoGmHpSARVumHtCZjaTpV38hN3TLUnNZAku3s1EmCHv7sGTVHmn7MkL5
s5oV64QgBd3zvWUUqmjSsQ6Ck2QwdacaWehz/It5pefCtR+r33XlwQmoVfV6f0iE
ZfVseoLRim79h+9qHBew3fqLqB5V+YHptNz2Wn4Wtdi9H4jeXQsmNl856eRzFYCq
cNqI9bEMSvkYGITusqcJMBZW5ZjK5R0V+cUu0QIDAQABAoIBACpHxaapfOJ56X26
O9+QHAt4C05WmXoYW8jHi8i/HVT/sE36LyJBIABzjBTb4t4bm8Y1mqTPBhadw/3l
6Qi/gZSRl/betNQ3j8xE1Vxeft9h6lpZ5fmnyTwbb24hPdiGc5Jr7J/kIH3+17Af
EzYXyO6cIqzcHgRV46jMcJrcOmHju8aPnV5B3wRAeKNOoBAUfT8iiCmLpvz1bXTo
Nysr+hRDNG1MsLcK+uktOZEg+mzyfhgFIZC66x4k05KL9xMM5OU1jtT0TSf0DvTg
OLboIFOzHVfaWZc66LLLr9vUcxOInrQmKAhPFHi35utJOPZjFtaLq8RDjNQO8PEG
S+mZLhUCgYEA5WMJVH8FD0rKDRr6TeaHrTHsamozdMUdNbDO2ZvMrnBcKCcd/TXw
HVZ7d06tNIgpMUwiwYNrNfwcBfJgkSiJ9DQRoq0NTAZQAQuMoOj2T9xySDt2jqGa
x3NvENN1iNeBwvq4A22zqkGyybfoGgD8lkPw9+mVjlW5IkP6pD85gvcCgYEA47Nz
tEmm2kpndP9fxGaHMpXDlC05LhpY9FqJpcVEyMQzhxhC9PwSZZvreC94t3nvveO/
ZT3NQ8NMgUy0C52yGuqFqxGiKt+hJnwVL6EnCX7BDBR8qEUbbL3VQv5JVnEmRQXc
80UkoYUulD9VJiLqvMvIQHBhqRvlEZE4hMTfoncCgYEAgheYwwMGq5WO4b/bFTMY
33Dg07lHVYI0/q43odJqUsQGf/8vUtu0Qe86Nn+4W4KdWggD7hvKQeOpQPYlLi3/
jy+4kLn0QJmT5gPWzatRhhlP9wdCRcIBNfyRkMlcby9JuHrYwZkFvBlmfGCAkb7d
gZsmnnMrDn4vcO98xonU5CECgYEA2OYsJWSzR+TwQAazVwbDanA26YNaoIwAiGNm
Ez6ikwwyeVGnFm63p4qq9sVhnITO1neH7gy85vu2eMR0DUyeR/12bspRS73SaDJy
i/hakzTm93bcd/28bg02hKZtfaYy6jT3j9QhXKrc/+KEXduM92K20os6vDgSMHXA
/Nf8n2kCgYEAw7JrSKQAVPjnFozOgp6TJ9wvI31Tp3aeU39VPias9qLTUW5g4Q7Z
bXCmDxoGi83N3tFWaHz30qPE3wRiFlBBaSV88pvGb52vhHgObIWJX1uTBtydPdE4
7nNWwL2V2NP2ieWMVznxEy4falJhSw9z+JmYAWRBKaalKGgYxOTVJDQ=
-----END RSA PRIVATE KEY-----
)PEM";

static const char* kTestAdminPublicKeyPem = R"PEM(-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzAedMnuIkQu+K2MfuHIS
bV5bsWTwAnKHjU4Hu+S+nKlfKqqcud1SMj7Hs/8qWwQgOtZqGEW5RL4hlYi8UpKV
LeJD1J7JG5Wv4ofc4vMcetcvX+6Dc1Z7Kbo1hoGmHpSARVumHtCZjaTpV38hN3TL
UnNZAku3s1EmCHv7sGTVHmn7MkL5s5oV64QgBd3zvWUUqmjSsQ6Ck2QwdacaWehz
/It5pefCtR+r33XlwQmoVfV6f0iEZfVseoLRim79h+9qHBew3fqLqB5V+YHptNz2
Wn4Wtdi9H4jeXQsmNl856eRzFYCqcNqI9bEMSvkYGITusqcJMBZW5ZjK5R0V+cUu
0QIDAQAB
-----END PUBLIC KEY-----
)PEM";

static int test_rng_cb(void*, unsigned char* out, size_t len) {
  esp_fill_random(out, len);
  return 0;
}

bool sign_rsa_pss_sha256_b64(const String& private_pem,
                                  const uint8_t* msg,
                                  size_t msg_len,
                                  String& out_sig_b64) {
  out_sig_b64 = "";
  uint8_t hash[32] = {0};
  if (!azt::sha256_bytes(msg, msg_len, hash)) return false;

  mbedtls_pk_context pk;
  mbedtls_pk_init(&pk);
  int rc = mbedtls_pk_parse_key(&pk,
                                reinterpret_cast<const unsigned char*>(private_pem.c_str()),
                                private_pem.length() + 1,
                                nullptr,
                                0);
  if (rc != 0) {
    mbedtls_pk_free(&pk);
    return false;
  }

  if (!mbedtls_pk_can_do(&pk, MBEDTLS_PK_RSA)) {
    mbedtls_pk_free(&pk);
    return false;
  }
  mbedtls_rsa_context* rsa = mbedtls_pk_rsa(pk);
  mbedtls_rsa_set_padding(rsa, MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA256);

  size_t sig_len = mbedtls_pk_get_len(&pk);
  std::vector<uint8_t> sig(sig_len, 0);
  rc = mbedtls_pk_sign(&pk, MBEDTLS_MD_SHA256, hash, sizeof(hash), sig.data(), &sig_len, test_rng_cb, nullptr);
  mbedtls_pk_free(&pk);
  if (rc != 0) return false;

  sig.resize(sig_len);
  out_sig_b64 = azt::b64(sig.data(), sig.size());
  return out_sig_b64.length() > 0;
}

void seed_device_sign_cache_for_config_tests() {
  Preferences p;
  p.begin("aztcfg", false);
  if (p.getString("dev_sign_pub", "").length() == 0) p.putString("dev_sign_pub", "TESTPUB");
  if (p.getString("dev_sign_fp", "").length() != 64) {
    p.putString("dev_sign_fp", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
  }
  p.end();
}

bool write_test_device_certificate(const String& device_pub_b64,
                                   const String& device_fp_hex,
                                   const String& device_chip_id_hex,
                                   const String& admin_fp_hex,
                                   const String& cert_serial,
                                   bool tamper_signature,
                                   bool tamper_device_fp) {
  String payload = "{";
  payload += "\"certificate_version\":1,";
  payload += "\"certificate_type\":\"device_key_binding\",";
  payload += "\"device_sign_public_key_b64\":\"" + device_pub_b64 + "\",";
  payload += "\"device_sign_fingerprint_hex\":\"" + (tamper_device_fp ? String("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb") : device_fp_hex) + "\",";
  payload += "\"device_chip_id_hex\":\"" + device_chip_id_hex + "\",";
  payload += "\"admin_signer_fingerprint_hex\":\"" + admin_fp_hex + "\",";
  payload += "\"valid_from_utc\":\"2026-03-14T00:00:00Z\",";
  payload += "\"valid_until_utc\":\"2036-03-14T00:00:00Z\",";
  payload += "\"certificate_serial\":\"" + cert_serial + "\",";
  payload += "\"signature_algorithm\":\"rsa-pss-sha256\"";
  payload += "}";

  String sig_b64;
  if (!sign_rsa_pss_sha256_b64(String(kTestAdminPrivateKeyPem), reinterpret_cast<const uint8_t*>(payload.c_str()), payload.length(), sig_b64)) {
    return false;
  }
  if (tamper_signature && sig_b64.length() > 3) sig_b64.setCharAt(2, sig_b64[2] == 'A' ? 'B' : 'A');

  String payload_b64 = azt::b64(reinterpret_cast<const uint8_t*>(payload.c_str()), payload.length());
  String cert_json = "{";
  cert_json += "\"certificate_payload_b64\":\"" + payload_b64 + "\",";
  cert_json += "\"signature_algorithm\":\"rsa-pss-sha256\",";
  cert_json += "\"signature_b64\":\"" + sig_b64 + "\"";
  cert_json += "}";

  Preferences p;
  p.begin("aztcfg", false);
  bool ok = p.putString("device_cert", cert_json) > 0;
  ok = ok && p.putString("dev_cert_sn", cert_serial) > 0;
  ok = ok && p.putString("disc_json", "{\"dummy\":true}") > 0;
  p.end();
  return ok;
}

bool test_config_save_load_roundtrip(Context& ctx) {
  seed_device_sign_cache_for_config_tests();
  if (!ctx.pubkey_pem || ctx.pubkey_pem->length() < 64) return false;
  String fp;
  if (!azt::compute_pubkey_spki_sha256_hex(*ctx.pubkey_pem, fp)) return false;

  azt::AppState st;
  bool ok = azt::save_config_state(st, *ctx.pubkey_pem, fp, "TestDevice", "ssid-test", "pass-test", true);
  if (!ok) return false;

  azt::AppState loaded;
  azt::load_config_state(loaded);
  return loaded.managed && loaded.signed_config_ready && loaded.admin_fingerprint_hex == fp &&
         loaded.wifi_ssid == "ssid-test" && loaded.wifi_pass == "pass-test";
}

bool test_config_signed_flag_transition(Context& ctx) {
  seed_device_sign_cache_for_config_tests();
  if (!ctx.pubkey_pem || ctx.pubkey_pem->length() < 64) return false;
  String fp;
  if (!azt::compute_pubkey_spki_sha256_hex(*ctx.pubkey_pem, fp)) return false;

  azt::AppState st;
  if (!azt::save_config_state(st, *ctx.pubkey_pem, fp, "TestDevice", "ssid-a", "pass-a", false)) return false;
  azt::AppState l1;
  azt::load_config_state(l1);
  if (!l1.managed || l1.signed_config_ready) return false;

  if (!azt::save_config_state(st, *ctx.pubkey_pem, fp, "TestDevice", "ssid-a", "pass-a", true)) return false;
  azt::AppState l2;
  azt::load_config_state(l2);
  return l2.managed && l2.signed_config_ready;
}

bool test_config_boot_cert_verify_valid(Context&) {
  seed_device_sign_cache_for_config_tests();

  String admin_fp;
  if (!azt::compute_pubkey_spki_sha256_hex(String(kTestAdminPublicKeyPem), admin_fp)) return false;

  azt::AppState current;
  azt::load_config_state(current);

  azt::AppState st;
  if (!azt::save_config_state(st, String(kTestAdminPublicKeyPem), admin_fp,
                              "TestDevice", "ssid-cert", "pass-cert", true)) return false;

  if (!write_test_device_certificate(current.device_sign_public_key_b64,
                                     current.device_sign_fingerprint_hex,
                                     current.device_chip_id_hex,
                                     admin_fp,
                                     "cert-valid-001",
                                     false,
                                     false)) {
    return false;
  }

  azt::AppState loaded;
  azt::load_config_state(loaded);
  return loaded.device_certificate_serial == "cert-valid-001";
}

bool test_config_recording_key_migration_from_admin(Context&) {
  seed_device_sign_cache_for_config_tests();

  String admin_fp;
  if (!azt::compute_pubkey_spki_sha256_hex(String(kTestAdminPublicKeyPem), admin_fp)) return false;

  Preferences p;
  p.begin("aztcfg", false);
  p.putBool("managed", true);
  p.putBool("signed_ok", true);
  p.putString("admin_pem", String(kTestAdminPublicKeyPem));
  p.putString("admin_fp", admin_fp);
  p.putString("dev_label", "MigDevice");
  p.putString("wifi_ssid", "ssid-mig");
  p.putString("wifi_pass", "pass-mig");
  p.remove("rec_pem");
  p.remove("rec_fp");
  p.end();

  azt::AppState loaded;
  azt::load_config_state(loaded);
  if (loaded.recording_pubkey_pem != loaded.admin_pubkey_pem) return false;
  if (loaded.recording_fingerprint_hex != loaded.admin_fingerprint_hex) return false;

  p.begin("aztcfg", true);
  String rec_pem = p.getString("rec_pem", "");
  String rec_fp = p.getString("rec_fp", "");
  p.end();
  return rec_pem == loaded.admin_pubkey_pem && rec_fp == loaded.admin_fingerprint_hex;
}

bool test_config_recording_key_migration_when_rec_fp_invalid(Context&) {
  seed_device_sign_cache_for_config_tests();

  String admin_fp;
  if (!azt::compute_pubkey_spki_sha256_hex(String(kTestAdminPublicKeyPem), admin_fp)) return false;

  Preferences p;
  p.begin("aztcfg", false);
  p.putBool("managed", true);
  p.putBool("signed_ok", true);
  p.putString("admin_pem", String(kTestAdminPublicKeyPem));
  p.putString("admin_fp", admin_fp);
  p.putString("rec_pem", String(kTestAdminPublicKeyPem));
  p.putString("rec_fp", "short");
  p.end();

  azt::AppState loaded;
  azt::load_config_state(loaded);
  if (loaded.recording_pubkey_pem != loaded.admin_pubkey_pem) return false;
  if (loaded.recording_fingerprint_hex != loaded.admin_fingerprint_hex) return false;
  return true;
}

bool test_config_recording_key_migration_when_rec_pem_missing(Context&) {
  seed_device_sign_cache_for_config_tests();

  String admin_fp;
  if (!azt::compute_pubkey_spki_sha256_hex(String(kTestAdminPublicKeyPem), admin_fp)) return false;

  Preferences p;
  p.begin("aztcfg", false);
  p.putBool("managed", true);
  p.putBool("signed_ok", true);
  p.putString("admin_pem", String(kTestAdminPublicKeyPem));
  p.putString("admin_fp", admin_fp);
  p.putString("rec_fp", admin_fp);
  p.remove("rec_pem");
  p.end();

  azt::AppState loaded;
  azt::load_config_state(loaded);
  return loaded.recording_pubkey_pem == loaded.admin_pubkey_pem &&
         loaded.recording_fingerprint_hex == loaded.admin_fingerprint_hex;
}

bool test_save_config_state_legacy_overload_sets_recording_from_admin(Context&) {
  seed_device_sign_cache_for_config_tests();

  String admin_fp;
  if (!azt::compute_pubkey_spki_sha256_hex(String(kTestAdminPublicKeyPem), admin_fp)) return false;

  azt::AppState st;
  if (!azt::save_config_state(st,
                              String(kTestAdminPublicKeyPem),
                              admin_fp,
                              "LegacySave",
                              "ssid-legacy",
                              "pass-legacy",
                              true)) {
    return false;
  }

  azt::AppState loaded;
  azt::load_config_state(loaded);
  return loaded.recording_pubkey_pem == loaded.admin_pubkey_pem &&
         loaded.recording_fingerprint_hex == loaded.admin_fingerprint_hex;
}

bool test_reset_managed_preserves_device_keys(Context&) {
  seed_device_sign_cache_for_config_tests();

  String admin_fp;
  if (!azt::compute_pubkey_spki_sha256_hex(String(kTestAdminPublicKeyPem), admin_fp)) return false;

  azt::AppState st;
  if (!azt::save_config_state(st, String(kTestAdminPublicKeyPem), admin_fp,
                              "ResetDevice", "ssid-r", "pass-r", true)) return false;

  if (!azt::reset_managed_config_preserve_device_keys(st)) return false;

  azt::AppState loaded;
  azt::load_config_state(loaded);

  bool managed_cleared = !loaded.managed && !loaded.signed_config_ready &&
                         loaded.admin_pubkey_pem.length() == 0 && loaded.admin_fingerprint_hex.length() == 0 &&
                         loaded.recording_pubkey_pem.length() == 0 && loaded.recording_fingerprint_hex.length() == 0 &&
                         loaded.wifi_ssid.length() == 0 && loaded.wifi_pass.length() == 0;

  bool device_keys_present = loaded.device_sign_public_key_b64.length() > 0 &&
                             loaded.device_sign_fingerprint_hex.length() == 64;

  return managed_cleared && device_keys_present;
}

bool test_invalid_cert_json_is_cleared_on_load(Context&) {
  seed_device_sign_cache_for_config_tests();

  Preferences p;
  p.begin("aztcfg", false);
  p.putString("device_cert", "{bad-json");
  p.putString("dev_cert_sn", "bad-cert-sn");
  p.putString("disc_json", "{\"stale\":true}");
  p.end();

  azt::AppState loaded;
  azt::load_config_state(loaded);

  if (loaded.device_certificate_serial.length() != 0) return false;

  p.begin("aztcfg", true);
  String cert = p.getString("device_cert", "");
  String cert_sn = p.getString("dev_cert_sn", "");
  String disc = p.getString("disc_json", "");
  p.end();

  return cert.length() == 0 && cert_sn.length() == 0 && disc.length() == 0;
}

bool test_tampered_cert_signature_is_cleared_on_load(Context&) {
  seed_device_sign_cache_for_config_tests();

  String admin_fp;
  if (!azt::compute_pubkey_spki_sha256_hex(String(kTestAdminPublicKeyPem), admin_fp)) return false;

  azt::AppState current;
  azt::load_config_state(current);

  azt::AppState st;
  if (!azt::save_config_state(st, String(kTestAdminPublicKeyPem), admin_fp,
                              "TestDevice", "ssid-cert", "pass-cert", true)) return false;

  if (!write_test_device_certificate(current.device_sign_public_key_b64,
                                     current.device_sign_fingerprint_hex,
                                     current.device_chip_id_hex,
                                     admin_fp,
                                     "cert-tampered-001",
                                     true,
                                     false)) {
    return false;
  }

  azt::AppState loaded;
  azt::load_config_state(loaded);

  if (loaded.device_certificate_serial.length() != 0) return false;

  Preferences p;
  p.begin("aztcfg", true);
  String cert = p.getString("device_cert", "");
  String cert_sn = p.getString("dev_cert_sn", "");
  p.end();

  return cert.length() == 0 && cert_sn.length() == 0;
}

bool test_cert_device_fp_mismatch_is_cleared_on_load(Context&) {
  seed_device_sign_cache_for_config_tests();

  String admin_fp;
  if (!azt::compute_pubkey_spki_sha256_hex(String(kTestAdminPublicKeyPem), admin_fp)) return false;

  azt::AppState current;
  azt::load_config_state(current);

  azt::AppState st;
  if (!azt::save_config_state(st, String(kTestAdminPublicKeyPem), admin_fp,
                              "TestDevice", "ssid-cert", "pass-cert", true)) return false;

  if (!write_test_device_certificate(current.device_sign_public_key_b64,
                                     current.device_sign_fingerprint_hex,
                                     current.device_chip_id_hex,
                                     admin_fp,
                                     "cert-fp-mismatch-001",
                                     false,
                                     true)) {
    return false;
  }

  azt::AppState loaded;
  azt::load_config_state(loaded);
  if (loaded.device_certificate_serial.length() != 0) return false;

  Preferences p;
  p.begin("aztcfg", true);
  String cert = p.getString("device_cert", "");
  String cert_sn = p.getString("dev_cert_sn", "");
  p.end();
  return cert.length() == 0 && cert_sn.length() == 0;
}

bool test_cert_admin_fp_mismatch_is_cleared_on_load(Context&) {
  seed_device_sign_cache_for_config_tests();

  String admin_fp;
  if (!azt::compute_pubkey_spki_sha256_hex(String(kTestAdminPublicKeyPem), admin_fp)) return false;

  azt::AppState current;
  azt::load_config_state(current);

  azt::AppState st;
  if (!azt::save_config_state(st, String(kTestAdminPublicKeyPem), admin_fp,
                              "TestDevice", "ssid-cert", "pass-cert", true)) return false;

  // Use a different admin fingerprint in cert payload to trigger mismatch.
  String bad_admin_fp = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
  if (!write_test_device_certificate(current.device_sign_public_key_b64,
                                     current.device_sign_fingerprint_hex,
                                     current.device_chip_id_hex,
                                     bad_admin_fp,
                                     "cert-admin-mismatch-001",
                                     false,
                                     false)) {
    return false;
  }

  azt::AppState loaded;
  azt::load_config_state(loaded);
  if (loaded.device_certificate_serial.length() != 0) return false;

  Preferences p;
  p.begin("aztcfg", true);
  String cert = p.getString("device_cert", "");
  String cert_sn = p.getString("dev_cert_sn", "");
  p.end();
  return cert.length() == 0 && cert_sn.length() == 0;
}

bool test_reset_managed_clears_persisted_cert_artifacts(Context&) {
  seed_device_sign_cache_for_config_tests();

  Preferences p;
  p.begin("aztcfg", false);
  p.putString("device_cert", "{\"dummy\":true}");
  p.putString("dev_cert_sn", "cert-reset-001");
  p.putString("disc_json", "{\"dummy\":true}");
  p.end();

  azt::AppState st;
  if (!azt::reset_managed_config_preserve_device_keys(st)) return false;

  p.begin("aztcfg", true);
  String cert = p.getString("device_cert", "");
  String cert_sn = p.getString("dev_cert_sn", "");
  String disc = p.getString("disc_json", "");
  p.end();

  return cert.length() == 0 && cert_sn.length() == 0 && disc.length() == 0;
}

bool test_reset_managed_clears_ota_override(Context&) {
  seed_device_sign_cache_for_config_tests();

  Preferences p;
  p.begin("aztcfg", false);
  p.putString("ota_signer_pem", "PEM_OVERRIDE");
  p.putString("ota_signer_fp", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
  p.end();

  azt::AppState st;
  st.ota_signer_override_public_key_pem = "PEM_OVERRIDE";
  st.ota_signer_override_fingerprint_hex = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

  if (!azt::reset_managed_config_preserve_device_keys(st)) return false;

  if (st.ota_signer_override_public_key_pem.length() != 0) return false;
  if (st.ota_signer_override_fingerprint_hex.length() != 0) return false;

  p.begin("aztcfg", true);
  String ota_pem = p.getString("ota_signer_pem", "");
  String ota_fp = p.getString("ota_signer_fp", "");
  p.end();

  return ota_pem.length() == 0 && ota_fp.length() == 0;
}

bool test_reset_managed_clears_state_cert_fields(Context&) {
  seed_device_sign_cache_for_config_tests();

  azt::AppState st;
  st.device_certificate_serial = "cert-state-001";
  st.discovery_announcement_json = "{\"x\":1}";

  if (!azt::reset_managed_config_preserve_device_keys(st)) return false;

  return st.device_certificate_serial.length() == 0 && st.discovery_announcement_json.length() == 0;
}

}  // namespace

void register_test_azt_config(Registry& out) {
  out.push_back({"CONFIG_SAVE_LOAD_ROUNDTRIP", test_config_save_load_roundtrip, "config save/load mismatch"});
  out.push_back({"CONFIG_SIGNED_FLAG_TRANSITION", test_config_signed_flag_transition, "config signed flag transition mismatch"});
  out.push_back({"CONFIG_BOOT_CERT_VERIFY_VALID", test_config_boot_cert_verify_valid, "boot cert verify valid path mismatch"});
  out.push_back({"CONFIG_RECORDING_KEY_MIGRATION_FROM_ADMIN", test_config_recording_key_migration_from_admin, "recording key migration from admin mismatch"});
  out.push_back({"CONFIG_RECORDING_KEY_MIGRATION_WHEN_REC_FP_INVALID", test_config_recording_key_migration_when_rec_fp_invalid, "recording key migration should recover invalid rec_fp"});
  out.push_back({"CONFIG_RECORDING_KEY_MIGRATION_WHEN_REC_PEM_MISSING", test_config_recording_key_migration_when_rec_pem_missing, "recording key migration should recover missing rec_pem"});
  out.push_back({"SAVE_CONFIG_STATE_LEGACY_OVERLOAD_SETS_RECORDING_FROM_ADMIN", test_save_config_state_legacy_overload_sets_recording_from_admin, "legacy save overload should mirror recording key from admin"});
  out.push_back({"RESET_MANAGED_PRESERVES_DEVICE_KEYS", test_reset_managed_preserves_device_keys, "managed reset should preserve device signing keys"});
  out.push_back({"INVALID_CERT_JSON_IS_CLEARED_ON_LOAD", test_invalid_cert_json_is_cleared_on_load, "invalid cert JSON should be purged on load"});
  out.push_back({"TAMPERED_CERT_SIGNATURE_IS_CLEARED_ON_LOAD", test_tampered_cert_signature_is_cleared_on_load, "tampered cert signature should be purged on load"});
  out.push_back({"CERT_DEVICE_FP_MISMATCH_IS_CLEARED_ON_LOAD", test_cert_device_fp_mismatch_is_cleared_on_load, "device fingerprint mismatch cert should be purged on load"});
  out.push_back({"CERT_ADMIN_FP_MISMATCH_IS_CLEARED_ON_LOAD", test_cert_admin_fp_mismatch_is_cleared_on_load, "admin fingerprint mismatch cert should be purged on load"});
  out.push_back({"RESET_MANAGED_CLEARS_PERSISTED_CERT_ARTIFACTS", test_reset_managed_clears_persisted_cert_artifacts, "reset should clear persisted cert/discovery artifacts"});
  out.push_back({"RESET_MANAGED_CLEARS_OTA_OVERRIDE", test_reset_managed_clears_ota_override, "reset should clear OTA signer override state/prefs"});
  out.push_back({"RESET_MANAGED_CLEARS_STATE_CERT_FIELDS", test_reset_managed_clears_state_cert_fields, "reset should clear cert/discovery fields in state"});
}

}  // namespace azt_test
