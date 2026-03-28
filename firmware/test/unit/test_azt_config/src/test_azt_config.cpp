#include "test_azt_registry.h"

#include <sodium.h>
#include <esp_system.h>
#include <Preferences.h>

#include <vector>

#include "azt_config.h"
#include "azt_crypto.h"

namespace azt_test {
namespace {

// Deterministic test-only Ed25519 signing identity. Never use in production.
static const unsigned char kTestAdminSeed[32] = {
  0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,
  0x39,0x30,0x61,0x62,0x63,0x64,0x65,0x66,
  0x41,0x42,0x43,0x44,0x45,0x46,0x47,0x48,
  0x49,0x4a,0x4b,0x4c,0x4d,0x4e,0x4f,0x50
};

bool test_admin_pub_b64_and_fp(String& out_pub_b64, String& out_fp_hex) {
  out_pub_b64 = "";
  out_fp_hex = "";
  if (sodium_init() < 0) return false;
  unsigned char pk[crypto_sign_ed25519_PUBLICKEYBYTES] = {0};
  unsigned char sk[crypto_sign_ed25519_SECRETKEYBYTES] = {0};
  if (crypto_sign_ed25519_seed_keypair(pk, sk, kTestAdminSeed) != 0) return false;
  out_pub_b64 = azt::b64(pk, sizeof(pk));
  uint8_t h[32] = {0};
  if (!azt::sha256_bytes(pk, sizeof(pk), h)) return false;
  out_fp_hex = azt::hex_lower(h, sizeof(h));
  return out_pub_b64.length() > 0 && out_fp_hex.length() == 64;
}

bool sign_ed25519_b64(const uint8_t* msg,
                      size_t msg_len,
                      String& out_sig_b64) {
  out_sig_b64 = "";
  if (sodium_init() < 0) return false;
  unsigned char pk[crypto_sign_ed25519_PUBLICKEYBYTES] = {0};
  unsigned char sk[crypto_sign_ed25519_SECRETKEYBYTES] = {0};
  if (crypto_sign_ed25519_seed_keypair(pk, sk, kTestAdminSeed) != 0) return false;
  unsigned char sig[crypto_sign_ed25519_BYTES] = {0};
  if (crypto_sign_ed25519_detached(sig, nullptr, msg, msg_len, sk) != 0) return false;
  out_sig_b64 = azt::b64(sig, sizeof(sig));
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
  payload += "\"signature_algorithm\":\"ed25519\"";
  payload += "}";

  String sig_b64;
  if (!sign_ed25519_b64(reinterpret_cast<const uint8_t*>(payload.c_str()), payload.length(), sig_b64)) {
    return false;
  }
  if (tamper_signature && sig_b64.length() > 3) sig_b64.setCharAt(2, sig_b64[2] == 'A' ? 'B' : 'A');

  String payload_b64 = azt::b64(reinterpret_cast<const uint8_t*>(payload.c_str()), payload.length());
  String cert_json = "{";
  cert_json += "\"certificate_payload_b64\":\"" + payload_b64 + "\",";
  cert_json += "\"signature_algorithm\":\"ed25519\",";
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
  String admin_pub_b64, fp;
  if (!test_admin_pub_b64_and_fp(admin_pub_b64, fp)) return false;

  azt::AppState st;
  bool ok = azt::save_config_state(st, admin_pub_b64, fp, "TestDevice", "ssid-test", "pass-test", true);
  if (!ok) return false;

  azt::AppState loaded;
  azt::load_config_state(loaded);
  return loaded.managed && loaded.signed_config_ready && loaded.admin_fingerprint_hex == fp &&
         loaded.wifi_ssid == "ssid-test" && loaded.wifi_pass == "pass-test";
}

bool test_config_signed_flag_transition(Context& ctx) {
  seed_device_sign_cache_for_config_tests();
  String admin_pub_b64, fp;
  if (!test_admin_pub_b64_and_fp(admin_pub_b64, fp)) return false;

  azt::AppState st;
  if (!azt::save_config_state(st, admin_pub_b64, fp, "TestDevice", "ssid-a", "pass-a", false)) return false;
  azt::AppState l1;
  azt::load_config_state(l1);
  if (!l1.managed || l1.signed_config_ready) return false;

  if (!azt::save_config_state(st, admin_pub_b64, fp, "TestDevice", "ssid-a", "pass-a", true)) return false;
  azt::AppState l2;
  azt::load_config_state(l2);
  return l2.managed && l2.signed_config_ready;
}

bool test_config_boot_cert_verify_valid(Context&) {
  seed_device_sign_cache_for_config_tests();

  String admin_pub_b64, admin_fp;
  if (!test_admin_pub_b64_and_fp(admin_pub_b64, admin_fp)) return false;

  azt::AppState current;
  azt::load_config_state(current);

  azt::AppState st;
  if (!azt::save_config_state(st, admin_pub_b64, admin_fp,
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

  String admin_pub_b64, admin_fp;
  if (!test_admin_pub_b64_and_fp(admin_pub_b64, admin_fp)) return false;

  Preferences p;
  p.begin("aztcfg", false);
  p.putBool("managed", true);
  p.putBool("signed_ok", true);
  p.putString("admin_pem", admin_pub_b64);
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

  String admin_pub_b64, admin_fp;
  if (!test_admin_pub_b64_and_fp(admin_pub_b64, admin_fp)) return false;

  Preferences p;
  p.begin("aztcfg", false);
  p.putBool("managed", true);
  p.putBool("signed_ok", true);
  p.putString("admin_pem", admin_pub_b64);
  p.putString("admin_fp", admin_fp);
  p.putString("rec_pem", admin_pub_b64);
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

  String admin_pub_b64, admin_fp;
  if (!test_admin_pub_b64_and_fp(admin_pub_b64, admin_fp)) return false;

  Preferences p;
  p.begin("aztcfg", false);
  p.putBool("managed", true);
  p.putBool("signed_ok", true);
  p.putString("admin_pem", admin_pub_b64);
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

  String admin_pub_b64, admin_fp;
  if (!test_admin_pub_b64_and_fp(admin_pub_b64, admin_fp)) return false;

  azt::AppState st;
  if (!azt::save_config_state(st,
                              admin_pub_b64,
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

  String admin_pub_b64, admin_fp;
  if (!test_admin_pub_b64_and_fp(admin_pub_b64, admin_fp)) return false;

  azt::AppState st;
  if (!azt::save_config_state(st, admin_pub_b64, admin_fp,
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

  String admin_pub_b64, admin_fp;
  if (!test_admin_pub_b64_and_fp(admin_pub_b64, admin_fp)) return false;

  azt::AppState current;
  azt::load_config_state(current);

  azt::AppState st;
  if (!azt::save_config_state(st, admin_pub_b64, admin_fp,
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

  String admin_pub_b64, admin_fp;
  if (!test_admin_pub_b64_and_fp(admin_pub_b64, admin_fp)) return false;

  azt::AppState current;
  azt::load_config_state(current);

  azt::AppState st;
  if (!azt::save_config_state(st, admin_pub_b64, admin_fp,
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

  String admin_pub_b64, admin_fp;
  if (!test_admin_pub_b64_and_fp(admin_pub_b64, admin_fp)) return false;

  azt::AppState current;
  azt::load_config_state(current);

  azt::AppState st;
  if (!azt::save_config_state(st, admin_pub_b64, admin_fp,
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
