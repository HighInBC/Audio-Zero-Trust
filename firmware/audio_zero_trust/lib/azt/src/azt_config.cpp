#include "azt_config.h"

#include <Preferences.h>
#include <sodium.h>
#include <ArduinoJson.h>
#include <esp_system.h>

#include "azt_constants.h"
#include "azt_crypto.h"
#include "azt_kv_store.h"

namespace azt {

static Preferences g_prefs;

static String device_chip_id_hex() {
  uint64_t chip = ESP.getEfuseMac();
  char b[17] = {0};
  snprintf(b, sizeof(b), "%016llx", static_cast<unsigned long long>(chip));
  return String(b);
}

static const char* reset_reason_to_string(esp_reset_reason_t reason) {
  switch (reason) {
    case ESP_RST_UNKNOWN: return "unknown";
    case ESP_RST_POWERON: return "poweron";
    case ESP_RST_EXT: return "external";
    case ESP_RST_SW: return "software";
    case ESP_RST_PANIC: return "panic";
    case ESP_RST_INT_WDT: return "int_wdt";
    case ESP_RST_TASK_WDT: return "task_wdt";
    case ESP_RST_WDT: return "other_wdt";
    case ESP_RST_DEEPSLEEP: return "deepsleep";
    case ESP_RST_BROWNOUT: return "brownout";
    case ESP_RST_SDIO: return "sdio";
    default: return "other";
  }
}

static bool is_unexpected_reset_reason(esp_reset_reason_t reason) {
  switch (reason) {
    case ESP_RST_PANIC:
    case ESP_RST_INT_WDT:
    case ESP_RST_TASK_WDT:
    case ESP_RST_WDT:
    case ESP_RST_BROWNOUT:
    case ESP_RST_UNKNOWN:
      return true;
    default:
      return false;
  }
}

static void record_boot_reset_state(AppState& state) {
  static bool recorded = false;
  if (recorded) return;
  recorded = true;

  const esp_reset_reason_t reason = esp_reset_reason();
  const bool unexpected = is_unexpected_reset_reason(reason);

  g_prefs.begin("aztcfg", false);
  uint32_t count = g_prefs.getUInt("unx_rst_cnt", 0);
  if (unexpected) {
    count += 1;
    g_prefs.putUInt("unx_rst_cnt", count);
  }
  g_prefs.putUInt("last_rst_reason", static_cast<uint32_t>(reason));
  g_prefs.putBool("last_rst_unexp", unexpected);
  g_prefs.end();

  state.last_reset_reason_code = static_cast<uint32_t>(reason);
  state.last_reset_reason = String(reset_reason_to_string(reason));
  state.last_reset_unexpected = unexpected;
  state.unexpected_reset_count = count;
}

static bool generate_device_ed25519(String& out_priv_b64,
                                    String& out_pub_b64,
                                    String& out_fp_hex) {
  out_priv_b64 = "";
  out_pub_b64 = "";
  out_fp_hex = "";

  if (sodium_init() < 0) return false;

  unsigned char pk[crypto_sign_ed25519_PUBLICKEYBYTES] = {0};
  unsigned char sk[crypto_sign_ed25519_SECRETKEYBYTES] = {0};
  if (crypto_sign_ed25519_keypair(pk, sk) != 0) return false;

  out_priv_b64 = b64(sk, sizeof(sk));
  out_pub_b64 = b64(pk, sizeof(pk));

  uint8_t h[32];
  if (!sha256_bytes(pk, sizeof(pk), h)) return false;
  out_fp_hex = hex_lower(h, sizeof(h));
  return out_priv_b64.length() > 0 && out_pub_b64.length() > 0 && out_fp_hex.length() == 64;
}

static bool ensure_device_keypair(AppState& state) {
  g_prefs.begin("aztcfg", true);
  String priv_b64 = kv_get_string(g_prefs, "dev_sign_priv", "");
  String pub_b64 = kv_get_string(g_prefs, "dev_sign_pub", "");
  String fp_hex = kv_get_string(g_prefs, "dev_sign_fp", "");
  g_prefs.end();

  if (priv_b64.length() > 0 && pub_b64.length() > 0 && fp_hex.length() == 64) {
    state.device_sign_public_key_b64 = pub_b64;
    state.device_sign_fingerprint_hex = fp_hex;
    return true;
  }

  // Required bootstrap behavior: missing device keypair invalidates prior config.
  g_prefs.begin("aztcfg", false);
  g_prefs.clear();
  g_prefs.end();

  if (!generate_device_ed25519(priv_b64, pub_b64, fp_hex)) return false;

  g_prefs.begin("aztcfg", false);
  bool ok = true;
  ok = ok && kv_set_string(g_prefs, "dev_sign_priv", priv_b64) > 0;
  ok = ok && kv_set_string(g_prefs, "dev_sign_pub", pub_b64) > 0;
  ok = ok && kv_set_string(g_prefs, "dev_sign_fp", fp_hex) > 0;
  g_prefs.end();

  if (!ok) return false;

  state.device_sign_public_key_b64 = pub_b64;
  state.device_sign_fingerprint_hex = fp_hex;
  state.managed = false;
  state.signed_config_ready = false;
  state.listener_pubkey_pem = "";
  state.listener_fingerprint_hex = "";
  state.recorder_auth_pubkey_b64 = "";
  state.recorder_auth_fingerprint_hex = "";
  state.device_label = "";
  state.wifi_mode = "sta";
  state.wifi_ssid = "";
  state.wifi_pass = "";
  state.wifi_ap_ssid = "";
  state.wifi_ap_pass = "";
  state.authorized_listener_ips_csv = "";
  state.time_servers_csv = "";
  state.mdns_enabled = false;
  state.mdns_hostname = "";
  state.mqtt_broker_url = "";
  state.mqtt_username = "";
  state.mqtt_password = "";
  state.mqtt_audio_rms_topic = "";
  state.mqtt_rms_window_seconds = 10;
  state.device_certificate_serial = "";
  state.device_certificate_json = "";
  state.discovery_announcement_json = "";
  state.tls_certificate_serial = "";
  state.tls_san_hosts_csv = "";
  state.stream_header_auto_record = true;
  state.stream_header_auto_decode = true;
  state.tls_server_cert_configured = false;
  state.tls_server_key_configured = false;
  state.tls_ca_cert_configured = false;
  return true;
}

static bool validate_stored_device_certificate(const AppState& state,
                                            const String& cert_json,
                                            String& out_cert_serial) {
  out_cert_serial = "";
  if (cert_json.length() == 0) return false;
  if (state.admin_pubkey_pem.length() == 0 || state.admin_fingerprint_hex.length() != 64) return false;

  JsonDocument cert_doc;
  if (deserializeJson(cert_doc, cert_json)) return false;

  String payload_b64 = String((const char*)(cert_doc["certificate_payload_b64"] | ""));
  String sig_alg = String((const char*)(cert_doc["signature_algorithm"] | ""));
  String sig_b64 = String((const char*)(cert_doc["signature_b64"] | ""));
  if (payload_b64.length() == 0 || sig_b64.length() == 0 || sig_alg != "ed25519") return false;

  std::vector<uint8_t> payload_raw;
  if (!b64_decode_vec(payload_b64, payload_raw) || payload_raw.empty()) return false;

  JsonDocument payload_doc;
  if (deserializeJson(payload_doc, payload_raw.data(), payload_raw.size())) return false;

  String dev_pub = String((const char*)(payload_doc["device_sign_public_key_b64"] | ""));
  String dev_fp = String((const char*)(payload_doc["device_sign_fingerprint_hex"] | ""));
  String chip_id = String((const char*)(payload_doc["device_chip_id_hex"] | ""));
  String admin_fp = String((const char*)(payload_doc["admin_signer_fingerprint_hex"] | ""));
  String cert_serial = String((const char*)(payload_doc["certificate_serial"] | ""));

  if (cert_serial.length() == 0) return false;
  if (dev_pub != state.device_sign_public_key_b64) return false;
  if (dev_fp != state.device_sign_fingerprint_hex) return false;
  if (chip_id != state.device_chip_id_hex) return false;
  if (admin_fp != state.admin_fingerprint_hex) return false;

  std::vector<uint8_t> admin_pub_raw;
  if (!b64_decode_vec(state.admin_pubkey_pem, admin_pub_raw)) return false;
  if (admin_pub_raw.size() != crypto_sign_ed25519_PUBLICKEYBYTES) return false;
  uint8_t h[32] = {0};
  if (!sha256_bytes(admin_pub_raw.data(), admin_pub_raw.size(), h)) return false;
  if (hex_lower(h, sizeof(h)) != state.admin_fingerprint_hex) return false;

  if (!verify_ed25519_signature_b64(state.admin_pubkey_pem, payload_raw, sig_b64)) return false;

  out_cert_serial = cert_serial;
  return true;
}

void load_config_state(AppState& state) {
  state.device_chip_id_hex = device_chip_id_hex();

  // First thing on boot: ensure device signing keypair exists.
  // If missing, config namespace is reset and a new Ed25519 keypair is created.
  ensure_device_keypair(state);

  g_prefs.begin("aztcfg", true);
  state.managed = g_prefs.getBool("managed", false);
  state.signed_config_ready = g_prefs.getBool("signed_ok", false);
  state.admin_pubkey_pem = kv_get_string(g_prefs, "admin_pem", "");
  state.admin_fingerprint_hex = kv_get_string(g_prefs, "admin_fp", "");
  state.listener_pubkey_pem = kv_get_string(g_prefs, "rec_pem", "");
  state.listener_fingerprint_hex = kv_get_string(g_prefs, "rec_fp", "");
  state.recorder_auth_pubkey_b64 = kv_get_string(g_prefs, "rec_auth_pub", "");
  state.recorder_auth_fingerprint_hex = kv_get_string(g_prefs, "rec_auth_fp", "");
  state.device_label = kv_get_string(g_prefs, "dev_label", "");
  state.wifi_mode = kv_get_string(g_prefs, "wifi_mode", "sta");
  state.wifi_mode.trim();
  state.wifi_mode.toLowerCase();
  if (state.wifi_mode != "sta" && state.wifi_mode != "ap") state.wifi_mode = "sta";
  state.wifi_ssid = kv_get_string(g_prefs, "wifi_ssid", "");
  state.wifi_pass = kv_get_string(g_prefs, "wifi_pass", "");
  state.wifi_ap_ssid = kv_get_string(g_prefs, "wifi_ap_ssid", "");
  state.wifi_ap_pass = kv_get_string(g_prefs, "wifi_ap_pass", "");
  state.authorized_listener_ips_csv = kv_get_string(g_prefs, "auth_ips", "");
  state.time_servers_csv = kv_get_string(g_prefs, "time_srv", "");
  state.mdns_enabled = g_prefs.getBool("mdns_en", false);
  state.mdns_hostname = kv_get_string(g_prefs, "mdns_host", "");
  state.mqtt_broker_url = kv_get_string(g_prefs, "mqtt_url", "");
  state.mqtt_username = kv_get_string(g_prefs, "mqtt_user", "");
  state.mqtt_password = kv_get_string(g_prefs, "mqtt_pass", "");
  state.mqtt_audio_rms_topic = kv_get_string(g_prefs, "mqtt_topic", "");
  state.mqtt_rms_window_seconds = static_cast<uint16_t>(g_prefs.getUShort("mqtt_rms_s", 10));
  if (state.mqtt_rms_window_seconds == 0) state.mqtt_rms_window_seconds = 10;
  state.stream_header_auto_record = g_prefs.getBool("hdr_auto_rec", true);
  state.stream_header_auto_decode = g_prefs.getBool("hdr_auto_dec", true);
  state.device_certificate_serial = kv_get_string(g_prefs, "dev_cert_sn", "");
  state.device_certificate_json = "";
  state.discovery_announcement_json = kv_get_string(g_prefs, "disc_json", "");
  state.tls_certificate_serial = kv_get_string(g_prefs, "tls_cert_sn", "");
  state.tls_san_hosts_csv = kv_get_string(g_prefs, "tls_san_csv", "");
  state.tls_server_cert_configured = kv_get_string(g_prefs, "tls_srv_cert", "").length() > 0;
  state.tls_server_key_configured = kv_get_string(g_prefs, "tls_srv_key", "").length() > 0;
  state.tls_ca_cert_configured = kv_get_string(g_prefs, "tls_ca_cert", "").length() > 0;
  state.device_sign_public_key_b64 = kv_get_string(g_prefs, "dev_sign_pub", state.device_sign_public_key_b64);
  state.device_sign_fingerprint_hex = kv_get_string(g_prefs, "dev_sign_fp", state.device_sign_fingerprint_hex);
  state.ota_signer_override_public_key_pem = kv_get_string(g_prefs, "ota_signer_pem", "");
  state.ota_signer_override_fingerprint_hex = kv_get_string(g_prefs, "ota_signer_fp", "");
  state.last_ota_version = kv_get_string(g_prefs, "ota_last_ver", "");
  // NVS key names max 15 chars. Use short keys and fall back to legacy names.
  state.last_ota_version_code = g_prefs.getULong64("ota_last_vc", 0);
  if (state.last_ota_version_code == 0) {
    state.last_ota_version_code = g_prefs.getULong64("ota_last_ver_code", 0);
  }
  state.ota_min_allowed_version_code = g_prefs.getULong64("ota_min_vc", 0);
  if (state.ota_min_allowed_version_code == 0) {
    state.ota_min_allowed_version_code = g_prefs.getULong64("ota_min_ver_code", 0);
  }
  state.config_revision = g_prefs.getUInt("cfg_rev", 0);
  state.audio_preamp_gain = static_cast<uint8_t>(g_prefs.getUChar("aud_micg", state.audio_preamp_gain));
  state.audio_adc_gain = static_cast<uint8_t>(g_prefs.getUChar("aud_adcg", state.audio_adc_gain));
  state.last_reset_reason_code = g_prefs.getUInt("last_rst_reason", 0);
  state.last_reset_unexpected = g_prefs.getBool("last_rst_unexp", false);
  state.unexpected_reset_count = g_prefs.getUInt("unx_rst_cnt", 0);
  state.last_reset_reason = String(reset_reason_to_string(static_cast<esp_reset_reason_t>(state.last_reset_reason_code)));
  String stored_cert_json = kv_get_string(g_prefs, "device_cert", "");
  g_prefs.end();

  // Capture this boot's reset reason (once per boot) and persist for /config/state.
  record_boot_reset_state(state);

  // Backward-compatible migration: if listener key was not stored, default it to admin key.
  if (state.listener_pubkey_pem.length() == 0 || state.listener_fingerprint_hex.length() != 64) {
    state.listener_pubkey_pem = state.admin_pubkey_pem;
    state.listener_fingerprint_hex = state.admin_fingerprint_hex;
    if (state.listener_pubkey_pem.length() > 0 && state.listener_fingerprint_hex.length() == 64) {
      g_prefs.begin("aztcfg", false);
      kv_set_string(g_prefs, "rec_pem", state.listener_pubkey_pem);
      kv_set_string(g_prefs, "rec_fp", state.listener_fingerprint_hex);
      g_prefs.end();
    }
  }

  if (stored_cert_json.length() > 0) {
    String cert_serial_verified;
    const bool cert_ok = validate_stored_device_certificate(state, stored_cert_json, cert_serial_verified);

    if (!cert_ok) {
      g_prefs.begin("aztcfg", false);
      kv_remove_key(g_prefs, "device_cert");
      kv_remove_key(g_prefs, "dev_cert_sn");
      kv_remove_key(g_prefs, "disc_json");
      g_prefs.end();
      state.device_certificate_serial = "";
      state.device_certificate_json = "";
      state.discovery_announcement_json = "";
    } else {
      if (state.device_certificate_serial != cert_serial_verified) {
        g_prefs.begin("aztcfg", false);
        kv_set_string(g_prefs, "dev_cert_sn", cert_serial_verified);
        g_prefs.end();
      }
      state.device_certificate_serial = cert_serial_verified;
      state.device_certificate_json = stored_cert_json;
    }
  }

}

bool save_config_state(AppState& state,
                       const String& admin_pem,
                       const String& admin_fp,
                       const String& listener_pem,
                       const String& listener_fp,
                       const String& recorder_auth_pub_b64,
                       const String& recorder_auth_fp,
                       const String& device_label,
                       const String& wifi_mode,
                       const String& wifi_ssid,
                       const String& wifi_pass,
                       const String& wifi_ap_ssid,
                       const String& wifi_ap_pass,
                       bool signed_ok,
                       const String& authorized_listener_ips_csv,
                       const String& time_servers_csv,
                       bool mdns_enabled,
                       const String& mdns_hostname) {
  g_prefs.begin("aztcfg", false);
  bool ok = true;
  const uint32_t next_rev = state.config_revision + 1;
  ok = ok && g_prefs.putBool("managed", true);
  ok = ok && g_prefs.putBool("signed_ok", signed_ok);
  ok = ok && g_prefs.putUInt("cfg_rev", next_rev);
  ok = ok && kv_set_string(g_prefs, "admin_pem", admin_pem) > 0;
  ok = ok && kv_set_string(g_prefs, "admin_fp", admin_fp) > 0;
  ok = ok && kv_set_string(g_prefs, "rec_pem", listener_pem) > 0;
  ok = ok && kv_set_string(g_prefs, "rec_fp", listener_fp) > 0;
  if (recorder_auth_pub_b64.length() > 0 && recorder_auth_fp.length() == 64) {
    ok = ok && kv_set_string(g_prefs, "rec_auth_pub", recorder_auth_pub_b64) > 0;
    ok = ok && kv_set_string(g_prefs, "rec_auth_fp", recorder_auth_fp) > 0;
  } else {
    kv_remove_key(g_prefs, "rec_auth_pub");
    kv_remove_key(g_prefs, "rec_auth_fp");
  }
  ok = ok && kv_set_string(g_prefs, "dev_label", device_label) > 0;
  ok = ok && kv_set_string(g_prefs, "wifi_mode", wifi_mode) > 0;
  if (wifi_mode == "ap") {
    ok = ok && kv_set_string(g_prefs, "wifi_ap_ssid", wifi_ap_ssid) > 0;
    ok = ok && kv_set_string(g_prefs, "wifi_ap_pass", wifi_ap_pass) > 0;
    kv_remove_key(g_prefs, "wifi_ssid");
    kv_remove_key(g_prefs, "wifi_pass");
  } else {
    ok = ok && kv_set_string(g_prefs, "wifi_ssid", wifi_ssid) > 0;
    ok = ok && kv_set_string(g_prefs, "wifi_pass", wifi_pass) > 0;
    kv_remove_key(g_prefs, "wifi_ap_ssid");
    kv_remove_key(g_prefs, "wifi_ap_pass");
  }
  if (authorized_listener_ips_csv.length() > 0) {
    ok = ok && kv_set_string(g_prefs, "auth_ips", authorized_listener_ips_csv) > 0;
  } else {
    kv_remove_key(g_prefs, "auth_ips");
  }
  if (time_servers_csv.length() > 0) {
    ok = ok && kv_set_string(g_prefs, "time_srv", time_servers_csv) > 0;
  } else {
    kv_remove_key(g_prefs, "time_srv");
  }
  ok = ok && g_prefs.putBool("mdns_en", mdns_enabled);
  ok = ok && g_prefs.putBool("hdr_auto_rec", state.stream_header_auto_record);
  ok = ok && g_prefs.putBool("hdr_auto_dec", state.stream_header_auto_decode);
  ok = ok && g_prefs.putUChar("aud_micg", state.audio_preamp_gain);
  ok = ok && g_prefs.putUChar("aud_adcg", state.audio_adc_gain);
  if (mdns_hostname.length() > 0) {
    ok = ok && kv_set_string(g_prefs, "mdns_host", mdns_hostname) > 0;
  } else {
    kv_remove_key(g_prefs, "mdns_host");
  }
  g_prefs.end();

  if (ok) {
    state.managed = true;
    state.signed_config_ready = signed_ok;
    state.admin_pubkey_pem = admin_pem;
    state.admin_fingerprint_hex = admin_fp;
    state.listener_pubkey_pem = listener_pem;
    state.listener_fingerprint_hex = listener_fp;
    state.recorder_auth_pubkey_b64 = recorder_auth_pub_b64;
    state.recorder_auth_fingerprint_hex = recorder_auth_fp;
    state.device_label = device_label;
    state.wifi_mode = wifi_mode;
    state.wifi_ssid = wifi_ssid;
    state.wifi_pass = wifi_pass;
    state.wifi_ap_ssid = wifi_ap_ssid;
    state.wifi_ap_pass = wifi_ap_pass;
    state.authorized_listener_ips_csv = authorized_listener_ips_csv;
    state.time_servers_csv = time_servers_csv;
    state.mdns_enabled = mdns_enabled;
    state.mdns_hostname = mdns_hostname;
    state.config_revision = next_rev;
  }
  return ok;
}

bool save_config_state(AppState& state,
                       const String& admin_pem,
                       const String& admin_fp,
                       const String& device_label,
                       const String& wifi_mode,
                       const String& wifi_ssid,
                       const String& wifi_pass,
                       const String& wifi_ap_ssid,
                       const String& wifi_ap_pass,
                       bool signed_ok,
                       const String& authorized_listener_ips_csv,
                       const String& time_servers_csv,
                       bool mdns_enabled,
                       const String& mdns_hostname) {
  return save_config_state(state,
                           admin_pem,
                           admin_fp,
                           admin_pem,
                           admin_fp,
                           "",
                           "",
                           device_label,
                           wifi_mode,
                           wifi_ssid,
                           wifi_pass,
                           wifi_ap_ssid,
                           wifi_ap_pass,
                           signed_ok,
                           authorized_listener_ips_csv,
                           time_servers_csv,
                           mdns_enabled,
                           mdns_hostname);
}

bool reset_managed_config_preserve_device_keys(AppState& state) {
  g_prefs.begin("aztcfg", false);
  kv_remove_key(g_prefs, "managed");
  kv_remove_key(g_prefs, "signed_ok");
  kv_remove_key(g_prefs, "admin_pem");
  kv_remove_key(g_prefs, "admin_fp");
  kv_remove_key(g_prefs, "rec_pem");
  kv_remove_key(g_prefs, "rec_fp");
  kv_remove_key(g_prefs, "rec_auth_pub");
  kv_remove_key(g_prefs, "rec_auth_fp");
  kv_remove_key(g_prefs, "wifi_mode");
  kv_remove_key(g_prefs, "wifi_ssid");
  kv_remove_key(g_prefs, "wifi_pass");
  kv_remove_key(g_prefs, "wifi_ap_ssid");
  kv_remove_key(g_prefs, "wifi_ap_pass");
  kv_remove_key(g_prefs, "auth_ips");
  kv_remove_key(g_prefs, "time_srv");
  kv_remove_key(g_prefs, "mdns_en");
  kv_remove_key(g_prefs, "mdns_host");
  kv_remove_key(g_prefs, "mqtt_url");
  kv_remove_key(g_prefs, "mqtt_user");
  kv_remove_key(g_prefs, "mqtt_pass");
  kv_remove_key(g_prefs, "mqtt_topic");
  kv_remove_key(g_prefs, "mqtt_rms_s");
  kv_remove_key(g_prefs, "hdr_auto_rec");
  kv_remove_key(g_prefs, "hdr_auto_dec");
  kv_remove_key(g_prefs, "device_cert");
  kv_remove_key(g_prefs, "dev_cert_sn");
  kv_remove_key(g_prefs, "disc_json");
  kv_remove_key(g_prefs, "ota_signer_pem");
  kv_remove_key(g_prefs, "ota_signer_fp");
  kv_remove_key(g_prefs, "tls_srv_key");
  kv_remove_key(g_prefs, "tls_srv_cert");
  kv_remove_key(g_prefs, "tls_ca_cert");
  kv_remove_key(g_prefs, "tls_cert_sn");
  kv_remove_key(g_prefs, "tls_san_csv");
  kv_remove_key(g_prefs, "cfg_rev");
  kv_remove_key(g_prefs, "aud_micg");
  kv_remove_key(g_prefs, "aud_adcg");
  g_prefs.end();

  state.managed = false;
  state.signed_config_ready = false;
  state.admin_pubkey_pem = "";
  state.admin_fingerprint_hex = "";
  state.listener_pubkey_pem = "";
  state.listener_fingerprint_hex = "";
  state.recorder_auth_pubkey_b64 = "";
  state.recorder_auth_fingerprint_hex = "";
  state.device_label = "";
  state.wifi_mode = "sta";
  state.wifi_ssid = "";
  state.wifi_pass = "";
  state.wifi_ap_ssid = "";
  state.wifi_ap_pass = "";
  state.authorized_listener_ips_csv = "";
  state.time_servers_csv = "";
  state.mdns_enabled = false;
  state.mdns_hostname = "";
  state.mqtt_broker_url = "";
  state.mqtt_username = "";
  state.mqtt_password = "";
  state.mqtt_audio_rms_topic = "";
  state.mqtt_rms_window_seconds = 10;
  state.device_certificate_serial = "";
  state.device_certificate_json = "";
  state.discovery_announcement_json = "";
  state.tls_certificate_serial = "";
  state.tls_san_hosts_csv = "";
  state.stream_header_auto_record = true;
  state.stream_header_auto_decode = true;
  state.tls_server_cert_configured = false;
  state.tls_server_key_configured = false;
  state.tls_ca_cert_configured = false;
  state.ota_signer_override_public_key_pem = "";
  state.ota_signer_override_fingerprint_hex = "";
  state.config_revision = 0;
  state.audio_echo_base_detected = false;
#if CONFIG_IDF_TARGET_ESP32S3
  state.audio_input_source = "none";
  state.audio_sample_rate_hz = 0;
  state.audio_channels = 0;
  state.audio_sample_width_bytes = 0;
#else
  state.audio_input_source = "internal_pdm";
  state.audio_sample_rate_hz = 16000;
  state.audio_channels = 1;
  state.audio_sample_width_bytes = 2;
#endif
  state.audio_preamp_gain = constants::audio::kDefaultPreampGain;
  state.audio_adc_gain = constants::audio::kDefaultAdcGain;

  return true;
}

}  // namespace azt
