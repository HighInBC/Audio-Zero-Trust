#include "azt_http_api.h"

#include <ArduinoJson.h>
#include <algorithm>
#include <vector>
#include <mbedtls/base64.h>
#include <IPAddress.h>
#include <Preferences.h>
#include <sodium.h>
#include <Update.h>
#include <mbedtls/sha256.h>
#include <esp_system.h>
#include <esp_ota_ops.h>
#include <esp_partition.h>
#include <esp_task_wdt.h>
#include <time.h>

#include "azt_config.h"
#include "azt_constants.h"
#include "azt_crypto.h"
#include "azt_discovery.h"
#include "azt_kv_store.h"
#include "azt_stream.h"

namespace azt {

#ifndef AZT_BUILD_NUMBER
#define AZT_BUILD_NUMBER 0
#endif

#ifndef AZT_BUILD_ID
#define AZT_BUILD_ID dev
#endif

#define AZT_STR2(x) #x
#define AZT_STR(x) AZT_STR2(x)

// Default embedded OTA signer key (ed25519 public_key_b64).
static const char* kOtaSignerPublicKeyPem = "6n6Ge+vZPN6HC+09FrDdBTlaEzQ0di799FuFCg+XR78=";

// Reboot challenge state (single active nonce).
static String g_reboot_nonce = "";
static uint32_t g_reboot_nonce_expires_ms = 0;

// OTA wake challenge + temporary open window state.
static String g_ota_wake_nonce = "";
static uint32_t g_ota_wake_nonce_expires_ms = 0;
static String g_ota_wake_allowed_ip = "";
static uint32_t g_ota_wake_open_expires_ms = 0;

// Stream access challenge state (single active nonce).
static String g_stream_nonce = "";
static uint32_t g_stream_nonce_expires_ms = 0;

// Certificate/TLS challenge state (single active nonce per operation).
static String g_cert_nonce = "";
static uint32_t g_cert_nonce_expires_ms = 0;
static String g_tls_cert_nonce = "";
static uint32_t g_tls_cert_nonce_expires_ms = 0;

static constexpr uint32_t kRebootNonceTtlMs = 10000;
static constexpr uint32_t kStreamNonceTtlMs = 15000;
static constexpr uint32_t kOtaWakeNonceTtlMs = 10000;
static constexpr uint32_t kOtaWakeWindowDefaultMs = 30000;
static constexpr uint32_t kOtaWakeWindowMinMs = 1000;
static constexpr uint32_t kOtaWakeWindowMaxMs = 120000;

static String json_quote(const String& in) {
  String out = "\"";
  for (size_t i = 0; i < in.length(); ++i) {
    char c = in[i];
    if (c == '\\' || c == '"') {
      out += '\\';
      out += c;
    } else if (c == '\n') {
      out += "\\n";
    } else if (c == '\r') {
      out += "\\r";
    } else if (c == '\t') {
      out += "\\t";
    } else {
      out += c;
    }
  }
  out += "\"";
  return out;
}


static String issue_single_use_nonce(String& out_nonce, uint32_t& out_expires_ms, uint32_t ttl_ms) {
  uint8_t rnd[16] = {0};
  esp_fill_random(rnd, sizeof(rnd));
  out_nonce = hex_lower(rnd, sizeof(rnd));
  out_expires_ms = millis() + ttl_ms;
  return out_nonce;
}

static bool validate_active_nonce(const String& provided,
                                  String& expected,
                                  uint32_t& expires_ms,
                                  uint32_t now_ms) {
  if (expected.length() == 0 || expires_ms == 0 || static_cast<int32_t>(now_ms - expires_ms) > 0) {
    expected = "";
    expires_ms = 0;
    return false;
  }
  return provided.length() > 0 && provided == expected;
}

static void consume_nonce(String& expected, uint32_t& expires_ms) {
  expected = "";
  expires_ms = 0;
}

static bool is_valid_ipv4_literal(const String& ip) {
  IPAddress parsed;
  return parsed.fromString(ip);
}

static String parse_query_param(const String& path, const char* key);

static void clear_ota_wake_window() {
  g_ota_wake_allowed_ip = "";
  g_ota_wake_open_expires_ms = 0;
}

static bool ota_wake_window_allows_ip(const String& remote_ip, uint32_t now_ms) {
  if (g_ota_wake_allowed_ip.length() == 0 || g_ota_wake_open_expires_ms == 0) {
    return false;
  }
  if (static_cast<int32_t>(now_ms - g_ota_wake_open_expires_ms) > 0) {
    clear_ota_wake_window();
    return false;
  }
  return remote_ip == g_ota_wake_allowed_ip;
}

static bool verify_stream_nonce_and_auth(const String& path,
                                         const AppState& state,
                                         String& out_nonce,
                                         String& out_err,
                                         String& out_detail) {
  out_nonce = parse_query_param(path, "nonce");
  out_detail = "";
  uint32_t now_ms = millis();
  if (!validate_active_nonce(out_nonce, g_stream_nonce, g_stream_nonce_expires_ms, now_ms)) {
    out_err = "ERR_STREAM_NONCE_REQUIRED";
    out_detail = "missing/expired nonce; fetch /api/v0/device/stream/challenge and retry";
    return false;
  }

  bool require_sig = state.recorder_auth_pubkey_b64.length() > 0 && state.recorder_auth_fingerprint_hex.length() == 64;
  if (require_sig) {
    String sig_alg = parse_query_param(path, "sig_alg");
    String sig_b64 = parse_query_param(path, "sig");
    String signer_fp = parse_query_param(path, "signer_fp");
    if (sig_alg != "ed25519" || sig_b64.length() == 0 || signer_fp != state.recorder_auth_fingerprint_hex) {
      out_err = "ERR_STREAM_AUTH_REQUIRED";
      out_detail = String("expected signer_fp=") + state.recorder_auth_fingerprint_hex + ", sig_alg=ed25519";
      return false;
    }
    String msg = String("stream:") + out_nonce + ":" + state.device_sign_fingerprint_hex;
    std::vector<uint8_t> msg_raw;
    msg_raw.reserve(msg.length());
    for (size_t i = 0; i < msg.length(); ++i) msg_raw.push_back(static_cast<uint8_t>(msg[i]));
    if (!verify_ed25519_signature_b64(state.recorder_auth_pubkey_b64, msg_raw, sig_b64)) {
      out_err = "ERR_STREAM_AUTH_VERIFY";
      out_detail = "signature verify failed for stream:<nonce>:<device_sign_fp>";
      return false;
    }
  }

  consume_nonce(g_stream_nonce, g_stream_nonce_expires_ms);
  return true;
}

static String wrap_pem(const char* begin_label, const char* end_label, const uint8_t* der, size_t der_len) {
  String b64der = b64(der, der_len);
  String out;
  out.reserve(strlen(begin_label) + strlen(end_label) + b64der.length() + 32);
  out += begin_label;
  out += "\n";
  for (size_t i = 0; i < b64der.length(); i += 64) {
    out += b64der.substring(i, std::min<size_t>(i + 64, b64der.length()));
    out += "\n";
  }
  out += end_label;
  out += "\n";
  return out;
}

static bool ed25519_pub_raw_to_spki_pem(const String& raw_b64, String& out_pem) {
  out_pem = "";
  std::vector<uint8_t> raw;
  if (!b64_decode_vec(raw_b64, raw)) return false;
  if (raw.size() != 32) return false;

  // DER SubjectPublicKeyInfo for Ed25519 (OID 1.3.101.112):
  // 30 2A 30 05 06 03 2B 65 70 03 21 00 <32-byte key>
  uint8_t der[44] = {
      0x30, 0x2A,
      0x30, 0x05,
      0x06, 0x03, 0x2B, 0x65, 0x70,
      0x03, 0x21, 0x00,
  };
  memcpy(der + 12, raw.data(), 32);

  out_pem = wrap_pem("-----BEGIN PUBLIC KEY-----", "-----END PUBLIC KEY-----", der, sizeof(der));
  return true;
}

static int hex_nibble(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
  if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
  return -1;
}

static String percent_decode(const String& in) {
  String out;
  out.reserve(in.length());
  for (size_t i = 0; i < in.length(); ++i) {
    char c = in[i];
    if (c == '%' && i + 2 < in.length()) {
      int hi = hex_nibble(in[i + 1]);
      int lo = hex_nibble(in[i + 2]);
      if (hi >= 0 && lo >= 0) {
        out += static_cast<char>((hi << 4) | lo);
        i += 2;
        continue;
      }
    }
    out += c;
  }
  return out;
}

static String parse_query_param(const String& path, const char* key) {
  int q = path.indexOf('?');
  if (q < 0) return "";
  String query = path.substring(q + 1);
  String token = String(key) + "=";
  int k = query.indexOf(token);
  if (k < 0) return "";
  int start = k + token.length();
  int end_amp = query.indexOf('&', start);
  int end_q = query.indexOf('?', start);
  int end = -1;
  if (end_amp >= 0 && end_q >= 0) {
    end = std::min(end_amp, end_q);
  } else if (end_amp >= 0) {
    end = end_amp;
  } else if (end_q >= 0) {
    end = end_q;
  }
  String v = (end < 0) ? query.substring(start) : query.substring(start, end);
  v = percent_decode(v);
  v.trim();
  return v;
}

static bool is_valid_attestation_nonce(const String& nonce) {
  if (nonce.length() < 8 || nonce.length() > 256) return false;
  for (size_t i = 0; i < nonce.length(); ++i) {
    char c = nonce[i];
    bool ok =
        (c >= 'a' && c <= 'z') ||
        (c >= 'A' && c <= 'Z') ||
        (c >= '0' && c <= '9') ||
        c == '-' || c == '_' || c == '.';
    if (!ok) return false;
  }
  return true;
}


static bool load_device_sign_sk(unsigned char out_sk[crypto_sign_ed25519_SECRETKEYBYTES]) {
  Preferences p;
  if (!p.begin("aztcfg", true)) return false;
  String sk_b64 = kv_get_string(p, "dev_sign_priv", "");
  p.end();
  if (sk_b64.length() == 0) return false;

  size_t olen = 0;
  int rc = mbedtls_base64_decode(out_sk,
                                 crypto_sign_ed25519_SECRETKEYBYTES,
                                 &olen,
                                 reinterpret_cast<const unsigned char*>(sk_b64.c_str()),
                                 sk_b64.length());
  if (rc != 0) return false;
  return olen == crypto_sign_ed25519_SECRETKEYBYTES;
}

static bool parse_wifi_values_variant(JsonVariant w, String& mode, String& ssid, String& pass, String& ap_ssid, String& ap_pass) {
  if (w.isNull() || !w.is<JsonObject>()) return false;
  String m = String((const char*)(w["mode"] | ""));
  m.trim();
  m.toLowerCase();
  if (m.length() == 0) m = "sta";
  if (m != "sta" && m != "ap") return false;

  if (m == "sta") {
    const char* s = w["ssid"] | "";
    const char* p = w["password"] | w["pass"] | "";
    if (strlen(s) == 0 || strlen(p) == 0) return false;
    ssid = String(s);
    pass = String(p);
    ap_ssid = String((const char*)(w["ap_ssid"] | ""));
    ap_pass = String((const char*)(w["ap_password"] | w["ap_pass"] | ""));
  } else {
    const char* s = w["ap_ssid"] | w["ssid"] | "";
    const char* p = w["ap_password"] | w["ap_pass"] | w["password"] | w["pass"] | "";
    if (strlen(s) == 0 || strlen(p) < 8) return false;
    ap_ssid = String(s);
    ap_pass = String(p);
  }

  mode = m;
  return true;
}

bool parse_wifi_values(JsonDocument& doc, String& mode, String& ssid, String& pass, String& ap_ssid, String& ap_pass) {
  return parse_wifi_values_variant(doc["wifi"], mode, ssid, pass, ap_ssid, ap_pass);
}

static bool is_valid_ipv4_str(const String& s) {
  IPAddress ip;
  return ip.fromString(s);
}

static bool is_valid_mdns_hostname_str(const String& s) {
  if (s.length() == 0) return true;
  if (s.length() > 63) return false;
  for (size_t i = 0; i < s.length(); ++i) {
    char c = s[i];
    bool ok =
        (c >= 'a' && c <= 'z') ||
        (c >= '0' && c <= '9') ||
        c == '-';
    if (!ok) return false;
  }
  if (s[0] == '-' || s[s.length() - 1] == '-') return false;
  return true;
}

static bool parse_authorized_listener_ips_variant(JsonVariant v, String& out_csv) {
  out_csv = "";
  if (v.isNull()) return true;  // optional
  if (!v.is<JsonArray>()) return false;

  JsonArray arr = v.as<JsonArray>();
  bool first = true;
  for (JsonVariant item : arr) {
    if (!item.is<const char*>()) return false;
    String ip = String(item.as<const char*>());
    ip.trim();
    if (!is_valid_ipv4_str(ip)) return false;
    if (!first) out_csv += ",";
    out_csv += ip;
    first = false;
  }
  return true;
}

static bool parse_authorized_listener_ips(JsonDocument& doc, String& out_csv) {
  return parse_authorized_listener_ips_variant(doc["authorized_listener_ips"], out_csv);
}

static bool parse_time_servers_variant(JsonVariant t, String& out_csv) {
  out_csv = "";
  if (t.isNull() || !t.is<JsonObject>()) return false;

  JsonVariant s = t["server"];
  if (s.is<const char*>()) {
    String server = String(s.as<const char*>());
    server.trim();
    if (server.length() == 0) return false;
    out_csv = server;
    return true;
  }

  JsonVariant a = t["servers"];
  if (a.isNull()) return false;
  if (!a.is<JsonArray>()) return false;
  bool first = true;
  for (JsonVariant item : a.as<JsonArray>()) {
    if (!item.is<const char*>()) return false;
    String server = String(item.as<const char*>());
    server.trim();
    if (server.length() == 0) return false;
    if (!first) out_csv += ",";
    out_csv += server;
    first = false;
  }
  return out_csv.length() > 0;
}

static bool parse_time_servers(JsonDocument& doc, String& out_csv) {
  return parse_time_servers_variant(doc["time"], out_csv);
}

static bool is_remote_ip_authorized(const AppState& state, const String& remote_ip) {
  if (state.authorized_listener_ips_csv.length() == 0) return true;

  int start = 0;
  while (start <= state.authorized_listener_ips_csv.length()) {
    int comma = state.authorized_listener_ips_csv.indexOf(',', start);
    String token = (comma < 0)
                       ? state.authorized_listener_ips_csv.substring(start)
                       : state.authorized_listener_ips_csv.substring(start, comma);
    token.trim();
    if (token == remote_ip) return true;
    if (comma < 0) break;
    start = comma + 1;
  }
  return false;
}

static bool parse_rsa_key_object(JsonDocument& doc,
                                 const char* field_name,
                                 String& out_pem,
                                 String& out_fp) {
  JsonVariant k = doc[field_name];
  if (k.isNull() || !k.is<JsonObject>()) return false;
  const char* alg = k["alg"] | "";
  const char* pem = k["public_key_pem"] | "";
  const char* fp_alg = k["fingerprint_alg"] | "";
  const char* fp_hex = k["fingerprint_hex"] | "";
  if (String(alg) != "rsa-oaep-sha256") return false;
  if (String(fp_alg) != "sha256-spki-der") return false;
  if (strlen(pem) < 32 || strlen(fp_hex) != 64) return false;
  String computed;
  if (!compute_pubkey_spki_sha256_hex(String(pem), computed)) return false;
  if (computed != String(fp_hex)) return false;
  out_pem = String(pem);
  out_fp = String(fp_hex);
  return true;
}

static bool parse_ed25519_key_object(JsonDocument& doc,
                                     const char* field_name,
                                     String& out_pub_b64,
                                     String& out_fp) {
  JsonVariant k = doc[field_name];
  if (k.isNull() || !k.is<JsonObject>()) return false;
  const char* alg = k["alg"] | "";
  const char* pub_b64 = k["public_key_b64"] | "";
  const char* fp_alg = k["fingerprint_alg"] | "";
  const char* fp_hex = k["fingerprint_hex"] | "";
  if (String(alg) != "ed25519") return false;
  if (String(fp_alg) != "sha256-raw-ed25519-pub") return false;
  if (strlen(pub_b64) == 0 || strlen(fp_hex) != 64) return false;

  std::vector<uint8_t> pub_raw;
  if (!b64_decode_vec(String(pub_b64), pub_raw)) return false;
  if (pub_raw.size() != crypto_sign_ed25519_PUBLICKEYBYTES) return false;

  uint8_t h[32] = {0};
  if (!sha256_bytes(pub_raw.data(), pub_raw.size(), h)) return false;
  if (hex_lower(h, sizeof(h)) != String(fp_hex)) return false;

  out_pub_b64 = String(pub_b64);
  out_fp = String(fp_hex);
  return true;
}

bool parse_header_key_values(JsonDocument& doc, String& admin_pem, String& admin_fp) {
  return parse_ed25519_key_object(doc, "admin_key", admin_pem, admin_fp);
}

static bool verify_config_signature_envelope(JsonDocument& doc,
                                             const String& expected_signer_fp,
                                             const String& signer_pub_pem,
                                             String& out_err_detail) {
  out_err_detail = "";

  String sig_alg = String((const char*)(doc["signature"]["alg"] | "none"));
  const char* signer_fp = doc["signature"]["signer_fingerprint_hex"] | "";
  const char* signed_payload_b64 = doc["signature"]["signed_payload_b64"] | "";
  const char* sig_b64 = doc["signature"]["sig_b64"] | "";

  if (sig_alg == "none") {
    out_err_detail = "signature alg none is not allowed";
    return false;
  }
  if (strlen(signer_fp) != 64 || strlen(signed_payload_b64) == 0 || strlen(sig_b64) == 0) {
    out_err_detail = "missing signature fields";
    return false;
  }
  if (String(signer_fp) != expected_signer_fp) {
    out_err_detail = "signer fingerprint does not match expected admin";
    return false;
  }

  std::vector<uint8_t> signed_payload_raw;
  if (!b64_decode_vec(String(signed_payload_b64), signed_payload_raw) || signed_payload_raw.empty()) {
    out_err_detail = "signed_payload_b64 invalid";
    return false;
  }

  if (!verify_ed25519_signature_b64(signer_pub_pem, signed_payload_raw, String(sig_b64))) {
    out_err_detail = "signature verification failed";
    return false;
  }

  JsonDocument unsigned_doc;
  unsigned_doc.set(doc);
  unsigned_doc.remove("signature");
  String canonical;
  serializeJson(unsigned_doc, canonical);

  String signed_payload_text;
  signed_payload_text.reserve(signed_payload_raw.size());
  for (uint8_t b : signed_payload_raw) signed_payload_text += static_cast<char>(b);

  if (signed_payload_text != canonical) {
    out_err_detail = "signed payload mismatch";
    return false;
  }

  return true;
}

static HttpDispatchResult handle_config_post_json(AppState& state,
                                                  const String& body,
                                                  bool allow_ota_signer_override) {
  HttpDispatchResult r{};
  r.content_type = "application/json";

  JsonDocument doc;
  DeserializationError err = deserializeJson(doc, body);
  if (err) {
    r.code = 400;
    r.body = "{\"ok\":false,\"error\":\"ERR_CONFIG_SCHEMA\",\"detail\":\"invalid json\",\"json_error\":" + json_quote(String(err.c_str())) + ",\"body_len\":" + String(body.length()) + "}";
    return r;
  }

  int v = doc["config_version"] | 0;
  if (v != 1) {
    r.code = 400;
    r.body = "{\"ok\":false,\"error\":\"ERR_CONFIG_SCHEMA\",\"detail\":\"config_version must be 1\"}";
    return r;
  }

  int if_version = doc["if_version"] | -1;
  if (if_version < 0 || static_cast<uint32_t>(if_version) != state.config_revision) {
    r.code = 409;
    r.body = "{\"ok\":false,\"error\":\"ERR_CONFIG_VERSION_CONFLICT\",\"expected\":" + String(state.config_revision) + ",\"provided\":" + String(if_version) + "}";
    return r;
  }

  String new_admin_pem, new_admin_fp;
  if (!parse_header_key_values(doc, new_admin_pem, new_admin_fp)) {
    r.code = 400;
    r.body = "{\"ok\":false,\"error\":\"ERR_CONFIG_SCHEMA\",\"detail\":\"invalid admin_key object\"}";
    return r;
  }

  String new_listener_pem = new_admin_pem;
  String new_listener_fp = new_admin_fp;
  JsonVariant lk = doc["listener_key"];
  if (!lk.isNull()) {
    if (!parse_rsa_key_object(doc, "listener_key", new_listener_pem, new_listener_fp)) {
      r.code = 400;
      r.body = "{\"ok\":false,\"error\":\"ERR_CONFIG_SCHEMA\",\"detail\":\"invalid listener_key object\"}";
      return r;
    }
  }

  String new_recorder_auth_pub = state.recorder_auth_pubkey_b64;
  String new_recorder_auth_fp = state.recorder_auth_fingerprint_hex;
  JsonVariant rk = doc["recorder_auth_key"];
  if (!rk.isNull()) {
    if (!parse_ed25519_key_object(doc, "recorder_auth_key", new_recorder_auth_pub, new_recorder_auth_fp)) {
      r.code = 400;
      r.body = "{\"ok\":false,\"error\":\"ERR_CONFIG_SCHEMA\",\"detail\":\"invalid recorder_auth_key object\"}";
      return r;
    }
  }

  String new_device_label = String((const char*)(doc["device_label"] | ""));
  new_device_label.trim();
  if (new_device_label.length() == 0) {
    r.code = 400;
    r.body = "{\"ok\":false,\"error\":\"ERR_CONFIG_SCHEMA\",\"detail\":\"device_label required\"}";
    return r;
  }

  String new_wifi_mode, new_wifi_ssid, new_wifi_pass, new_wifi_ap_ssid, new_wifi_ap_pass;
  if (!parse_wifi_values(doc, new_wifi_mode, new_wifi_ssid, new_wifi_pass, new_wifi_ap_ssid, new_wifi_ap_pass)) {
     r.code = 400;
     r.body = "{\"ok\":false,\"error\":\"ERR_CONFIG_SCHEMA\",\"detail\":\"invalid wifi object\"}";
     return r;
   }

  String auth_ips_csv;
  if (!parse_authorized_listener_ips(doc, auth_ips_csv)) {
    r.code = 400;
    r.body = "{\"ok\":false,\"error\":\"ERR_CONFIG_SCHEMA\",\"detail\":\"invalid authorized_listener_ips (must be IPv4 string array)\"}";
    return r;
  }

  String time_servers_csv;
  if (!parse_time_servers(doc, time_servers_csv)) {
    r.code = 400;
    r.body = "{\"ok\":false,\"error\":\"ERR_CONFIG_SCHEMA\",\"detail\":\"invalid time config (time.server or time.servers required)\"}";
    return r;
  }

  bool new_mdns_enabled = state.mdns_enabled;
  String new_mdns_hostname = state.mdns_hostname;
  bool new_stream_header_auto_record = state.stream_header_auto_record;
  bool new_stream_header_auto_decode = state.stream_header_auto_decode;
  uint8_t new_audio_preamp_gain = state.audio_preamp_gain;
  uint8_t new_audio_adc_gain = state.audio_adc_gain;
  JsonVariant mdns = doc["mdns"];
  if (!mdns.isNull()) {
    if (!mdns.is<JsonObject>()) {
      r.code = 400;
      r.body = "{\"ok\":false,\"error\":\"ERR_CONFIG_SCHEMA\",\"detail\":\"invalid mdns object\"}";
      return r;
    }
    new_mdns_enabled = mdns["enabled"] | false;
    new_mdns_hostname = String((const char*)(mdns["hostname"] | ""));
    new_mdns_hostname.trim();
    new_mdns_hostname.toLowerCase();
    if (!is_valid_mdns_hostname_str(new_mdns_hostname)) {
      r.code = 400;
      r.body = "{\"ok\":false,\"error\":\"ERR_CONFIG_SCHEMA\",\"detail\":\"invalid mdns.hostname\"}";
      return r;
    }
  }

  String new_mqtt_broker_url = state.mqtt_broker_url;
  String new_mqtt_username = state.mqtt_username;
  String new_mqtt_password = state.mqtt_password;
  String new_mqtt_audio_rms_topic = state.mqtt_audio_rms_topic;
  uint16_t new_mqtt_rms_window_seconds = state.mqtt_rms_window_seconds > 0 ? state.mqtt_rms_window_seconds : 10;

  JsonVariant mqtt = doc["mqtt"];
  if (!mqtt.isNull()) {
    if (!mqtt.is<JsonObject>()) {
      r.code = 400;
      r.body = "{\"ok\":false,\"error\":\"ERR_CONFIG_SCHEMA\",\"detail\":\"invalid mqtt object\"}";
      return r;
    }
    if (!mqtt["broker_url"].isNull()) new_mqtt_broker_url = String((const char*)(mqtt["broker_url"] | ""));
    if (!mqtt["username"].isNull()) new_mqtt_username = String((const char*)(mqtt["username"] | ""));
    if (!mqtt["password"].isNull()) new_mqtt_password = String((const char*)(mqtt["password"] | ""));
    if (!mqtt["audio_rms_topic"].isNull()) new_mqtt_audio_rms_topic = String((const char*)(mqtt["audio_rms_topic"] | ""));
    if (!mqtt["rms_window_seconds"].isNull()) {
      int v = mqtt["rms_window_seconds"].as<int>();
      if (v < 1 || v > 3600) {
        r.code = 400;
        r.body = "{\"ok\":false,\"error\":\"ERR_CONFIG_SCHEMA\",\"detail\":\"invalid mqtt.rms_window_seconds (1..3600)\"}";
        return r;
      }
      new_mqtt_rms_window_seconds = static_cast<uint16_t>(v);
    }
    new_mqtt_broker_url.trim();
    new_mqtt_username.trim();
    new_mqtt_password.trim();
    new_mqtt_audio_rms_topic.trim();
    if (new_mqtt_broker_url.length() > 0 && new_mqtt_audio_rms_topic.length() == 0) {
      r.code = 400;
      r.body = "{\"ok\":false,\"error\":\"ERR_CONFIG_SCHEMA\",\"detail\":\"mqtt.audio_rms_topic required when mqtt.broker_url is set\"}";
      return r;
    }
  }

  JsonVariant audio = doc["audio"];
  if (!audio.isNull()) {
    if (!audio.is<JsonObject>()) {
      r.code = 400;
      r.body = "{\"ok\":false,\"error\":\"ERR_CONFIG_SCHEMA\",\"detail\":\"invalid audio object\"}";
      return r;
    }
    if (!audio["preamp_gain"].isNull()) {
      int v = audio["preamp_gain"].as<int>();
      if (v < constants::audio::kPreampGainMin || v > constants::audio::kPreampGainMax) {
        r.code = 400;
        r.body = String("{\"ok\":false,\"error\":\"ERR_CONFIG_SCHEMA\",\"detail\":\"") + constants::audio::kPreampRangeDetail + "\"}";
        return r;
      }
      new_audio_preamp_gain = static_cast<uint8_t>(v);
    }
    if (!audio["adc_gain"].isNull()) {
      int v = audio["adc_gain"].as<int>();
      if (v < constants::audio::kAdcGainMin || v > constants::audio::kAdcGainMax) {
        r.code = 400;
        r.body = String("{\"ok\":false,\"error\":\"ERR_CONFIG_SCHEMA\",\"detail\":\"") + constants::audio::kAdcRangeDetail + "\"}";
        return r;
      }
      new_audio_adc_gain = static_cast<uint8_t>(v);
    }
  }

  JsonVariant shf = doc["stream_header_flags"];
  if (!shf.isNull()) {
    if (!shf.is<JsonObject>()) {
      r.code = 400;
      r.body = "{\"ok\":false,\"error\":\"ERR_CONFIG_SCHEMA\",\"detail\":\"invalid stream_header_flags object\"}";
      return r;
    }
    if (!shf["auto_record"].isNull()) {
      new_stream_header_auto_record = shf["auto_record"].as<bool>();
    }
    if (!shf["auto_decode"].isNull()) {
      new_stream_header_auto_decode = shf["auto_decode"].as<bool>();
    }
  }

  bool tls_set = false;
  bool tls_was_configured = state.tls_server_cert_configured && state.tls_server_key_configured;
  String tls_cert_serial = "";
  String tls_srv_cert = "";
  String tls_srv_key = "";
  String tls_ca_cert = "";
  String tls_san_csv = "";
  JsonVariant tls = doc["tls"];
  if (!tls.isNull()) {
    if (!tls.is<JsonObject>()) {
      r.code = 400;
      r.body = "{\"ok\":false,\"error\":\"ERR_CONFIG_SCHEMA\",\"detail\":\"invalid tls object\"}";
      return r;
    }
    tls_set = true;
    tls_cert_serial = String((const char*)(tls["tls_certificate_serial"] | ""));
    tls_srv_cert = String((const char*)(tls["tls_server_certificate_pem"] | ""));
    tls_srv_key = String((const char*)(tls["tls_server_private_key_pem"] | ""));
    tls_ca_cert = String((const char*)(tls["tls_ca_certificate_pem"] | ""));
    JsonVariant tls_san_hosts = tls["tls_san_hosts"];
    if (!tls_san_hosts.isNull()) {
      if (!tls_san_hosts.is<JsonArray>()) {
        r.code = 400;
        r.body = "{\"ok\":false,\"error\":\"ERR_CONFIG_SCHEMA\",\"detail\":\"tls_san_hosts must be array\"}";
        return r;
      }
      bool first = true;
      for (JsonVariant v : tls_san_hosts.as<JsonArray>()) {
        String h = String((const char*)(v | ""));
        h.trim();
        if (h.length() == 0) continue;
        if (!first) tls_san_csv += ",";
        tls_san_csv += h;
        first = false;
      }
    }
    tls_cert_serial.trim();
    tls_srv_cert.trim();
    tls_srv_key.trim();
    tls_ca_cert.trim();
    if (tls_cert_serial.length() == 0 || tls_srv_cert.length() == 0 || tls_srv_key.length() == 0) {
      r.code = 400;
      r.body = "{\"ok\":false,\"error\":\"ERR_CONFIG_SCHEMA\",\"detail\":\"tls requires serial/server certificate/private key\"}";
      return r;
    }
  }

  String ota_signer_pem = String((const char*)(doc["ota_signer_public_key_pem"] | ""));
  ota_signer_pem.trim();
  bool ota_signer_clear = doc["ota_signer_clear"] | false;

  bool ota_version_set = !doc["ota_version_code"].isNull();
  uint64_t ota_version_value = 0;
  bool ota_floor_set = !doc["ota_min_allowed_version_code"].isNull();
  bool ota_floor_clear = doc["ota_min_allowed_version_code_clear"] | false;
  uint64_t ota_floor_value = 0;
  if (ota_version_set) {
    JsonVariantConst vv = doc["ota_version_code"];
    if (vv.is<uint64_t>()) {
      ota_version_value = vv.as<uint64_t>();
    } else if (vv.is<unsigned long>()) {
      ota_version_value = static_cast<uint64_t>(vv.as<unsigned long>());
    } else if (vv.is<const char*>()) {
      const char* s = vv.as<const char*>();
      char* end = nullptr;
      unsigned long long parsed = strtoull(s ? s : "", &end, 10);
      if (!end || *end != '\0') {
        r.code = 400;
        r.body = "{\"ok\":false,\"error\":\"ERR_CONFIG_SCHEMA\",\"detail\":\"invalid ota_version_code\"}";
        return r;
      }
      ota_version_value = static_cast<uint64_t>(parsed);
    } else {
      r.code = 400;
      r.body = "{\"ok\":false,\"error\":\"ERR_CONFIG_SCHEMA\",\"detail\":\"invalid ota_version_code\"}";
      return r;
    }
  }

  if (ota_floor_set) {
    JsonVariantConst vf = doc["ota_min_allowed_version_code"];
    if (vf.is<uint64_t>()) {
      ota_floor_value = vf.as<uint64_t>();
    } else if (vf.is<unsigned long>()) {
      ota_floor_value = static_cast<uint64_t>(vf.as<unsigned long>());
    } else if (vf.is<const char*>()) {
      const char* s = vf.as<const char*>();
      char* end = nullptr;
      unsigned long long parsed = strtoull(s ? s : "", &end, 10);
      if (!end || *end != '\0') {
        r.code = 400;
        r.body = "{\"ok\":false,\"error\":\"ERR_CONFIG_SCHEMA\",\"detail\":\"invalid ota_min_allowed_version_code\"}";
        return r;
      }
      ota_floor_value = static_cast<uint64_t>(parsed);
    } else {
      r.code = 400;
      r.body = "{\"ok\":false,\"error\":\"ERR_CONFIG_SCHEMA\",\"detail\":\"invalid ota_min_allowed_version_code\"}";
      return r;
    }
  }

  if ((ota_signer_pem.length() > 0 || ota_signer_clear || ota_version_set || ota_floor_set || ota_floor_clear) && !allow_ota_signer_override) {
    r.code = 403;
    r.body = "{\"ok\":false,\"error\":\"ERR_CONFIG_OTA_SERIAL_ONLY\",\"detail\":\"ota signer/floor controls are serial-configurable only\"}";
    return r;
  }

  if (ota_floor_set && !ota_version_set) {
    r.code = 400;
    r.body = "{\"ok\":false,\"error\":\"ERR_CONFIG_SCHEMA\",\"detail\":\"ota_version_code required when ota_min_allowed_version_code is set\"}";
    return r;
  }

  const bool listener_key_changed =
      (new_listener_pem != state.listener_pubkey_pem) ||
      (new_listener_fp != state.listener_fingerprint_hex);

  String sig_err;
  if (!state.managed) {
    if (!verify_config_signature_envelope(doc, new_admin_fp, new_admin_pem, sig_err)) {
      r.code = 401;
      r.body = "{\"ok\":false,\"error\":\"ERR_CONFIG_SIGNATURE\",\"detail\":" + json_quote(sig_err) + "}";
      return r;
    }

    state.audio_preamp_gain = new_audio_preamp_gain;
    state.audio_adc_gain = new_audio_adc_gain;
    state.stream_header_auto_record = new_stream_header_auto_record;
    state.stream_header_auto_decode = new_stream_header_auto_decode;
    if (!save_config_state(state, new_admin_pem, new_admin_fp, new_listener_pem, new_listener_fp, new_recorder_auth_pub, new_recorder_auth_fp, new_device_label, new_wifi_mode, new_wifi_ssid, new_wifi_pass, new_wifi_ap_ssid, new_wifi_ap_pass, true, auth_ips_csv, time_servers_csv, new_mdns_enabled, new_mdns_hostname)) {
      r.code = 500;
      r.body = "{\"ok\":false,\"error\":\"ERR_CONFIG_STATE\",\"detail\":\"failed to persist config\"}";
      return r;
    }
    {
      Preferences mp;
      if (mp.begin("aztcfg", false)) {
        if (new_mqtt_broker_url.length() > 0) kv_set_string(mp, "mqtt_url", new_mqtt_broker_url); else kv_remove_key(mp, "mqtt_url");
        if (new_mqtt_username.length() > 0) kv_set_string(mp, "mqtt_user", new_mqtt_username); else kv_remove_key(mp, "mqtt_user");
        if (new_mqtt_password.length() > 0) kv_set_string(mp, "mqtt_pass", new_mqtt_password); else kv_remove_key(mp, "mqtt_pass");
        if (new_mqtt_audio_rms_topic.length() > 0) kv_set_string(mp, "mqtt_topic", new_mqtt_audio_rms_topic); else kv_remove_key(mp, "mqtt_topic");
        mp.putUShort("mqtt_rms_s", new_mqtt_rms_window_seconds > 0 ? new_mqtt_rms_window_seconds : 10);
        mp.end();
      }
      state.mqtt_broker_url = new_mqtt_broker_url;
      state.mqtt_username = new_mqtt_username;
      state.mqtt_password = new_mqtt_password;
      state.mqtt_audio_rms_topic = new_mqtt_audio_rms_topic;
      state.mqtt_rms_window_seconds = new_mqtt_rms_window_seconds > 0 ? new_mqtt_rms_window_seconds : 10;
    }
    state.discovery_announcement_json = build_discovery_announcement_json(state, kHttpPort);
    Preferences p;
    if (p.begin("aztcfg", false)) {
      kv_set_string(p, "disc_json", state.discovery_announcement_json);
      p.end();
    }

    if (tls_set) {
      Preferences tp;
      if (tp.begin("aztcfg", false)) {
        bool ok_put = true;
        ok_put = ok_put && kv_set_string(tp, "tls_srv_key", tls_srv_key) > 0;
        ok_put = ok_put && kv_set_string(tp, "tls_srv_cert", tls_srv_cert) > 0;
        if (tls_ca_cert.length() > 0) {
          ok_put = ok_put && kv_set_string(tp, "tls_ca_cert", tls_ca_cert) > 0;
        }
        ok_put = ok_put && kv_set_string(tp, "tls_cert_sn", tls_cert_serial) > 0;
        if (tls_san_csv.length() > 0) {
          ok_put = ok_put && kv_set_string(tp, "tls_san_csv", tls_san_csv) > 0;
        } else {
          kv_remove_key(tp, "tls_san_csv");
        }
        tp.end();
        if (!ok_put) {
          r.code = 500;
          r.body = "{\"ok\":false,\"error\":\"ERR_CONFIG_TLS_STORE\",\"detail\":\"failed to persist tls config\"}";
          return r;
        }
      }
      state.tls_server_key_configured = true;
      state.tls_server_cert_configured = true;
      state.tls_ca_cert_configured = tls_ca_cert.length() > 0;
      state.tls_certificate_serial = tls_cert_serial;
      state.tls_san_hosts_csv = tls_san_csv;
    }

    if (allow_ota_signer_override && (ota_signer_pem.length() > 0 || ota_signer_clear || ota_version_set || ota_floor_set || ota_floor_clear)) {
      Preferences op;
      if (op.begin("aztcfg", false)) {
        if (ota_signer_clear) {
          kv_remove_key(op, "ota_signer_pem");
          kv_remove_key(op, "ota_signer_fp");
          state.ota_signer_override_public_key_pem = "";
          state.ota_signer_override_fingerprint_hex = "";
        } else if (ota_signer_pem.length() > 0) {
          String ota_fp;
          std::vector<uint8_t> ota_pub_raw;
          if (!b64_decode_vec(ota_signer_pem, ota_pub_raw) || ota_pub_raw.size() != crypto_sign_ed25519_PUBLICKEYBYTES) {
            op.end();
            r.code = 400;
            r.body = "{\"ok\":false,\"error\":\"ERR_CONFIG_OTA_SIGNER\",\"detail\":\"invalid ota signer key (expected ed25519 public_key_b64)\"}";
            return r;
          }
          uint8_t h[32] = {0};
          if (!sha256_bytes(ota_pub_raw.data(), ota_pub_raw.size(), h)) {
            op.end();
            r.code = 400;
            r.body = "{\"ok\":false,\"error\":\"ERR_CONFIG_OTA_SIGNER\",\"detail\":\"invalid ota signer hash\"}";
            return r;
          }
          ota_fp = hex_lower(h, sizeof(h));
          kv_set_string(op, "ota_signer_pem", ota_signer_pem);
          kv_set_string(op, "ota_signer_fp", ota_fp);
          state.ota_signer_override_public_key_pem = ota_signer_pem;
          state.ota_signer_override_fingerprint_hex = ota_fp;
        }

        if (ota_version_set) {
          op.putULong64("ota_last_vc", ota_version_value);
          state.last_ota_version_code = ota_version_value;
          state.last_ota_version = String((unsigned long long)ota_version_value);
          kv_set_string(op, "ota_last_ver", state.last_ota_version);
        }

        if (ota_floor_clear) {
          kv_remove_key(op, "ota_min_vc");
          kv_remove_key(op, "ota_min_ver_code");
          state.ota_min_allowed_version_code = 0;
        } else if (ota_floor_set) {
          op.putULong64("ota_min_vc", ota_floor_value);
          state.ota_min_allowed_version_code = ota_floor_value;
        }

        op.end();
      }
    }

    if (listener_key_changed) {
      request_stream_shutdown();
    }

    r.code = 200;
    r.body = "{\"ok\":true,\"state\":\"MANAGED\",\"signed_config_ready\":true,\"admin_fingerprint_hex\":\"" + state.admin_fingerprint_hex + "\",\"config_revision\":" + String(state.config_revision) + "}";
    if (tls_set) {
      r.reboot_after_response = true;
    }
    return r;
  }

  if (!verify_config_signature_envelope(doc, state.admin_fingerprint_hex, state.admin_pubkey_pem, sig_err)) {
    r.code = 401;
    r.body = "{\"ok\":false,\"error\":\"ERR_CONFIG_SIGNATURE\",\"detail\":" + json_quote(sig_err) + "}";
    return r;
  }

  state.audio_preamp_gain = new_audio_preamp_gain;
  state.audio_adc_gain = new_audio_adc_gain;
  state.stream_header_auto_record = new_stream_header_auto_record;
  state.stream_header_auto_decode = new_stream_header_auto_decode;
  if (!save_config_state(state, new_admin_pem, new_admin_fp, new_listener_pem, new_listener_fp, new_recorder_auth_pub, new_recorder_auth_fp, new_device_label, new_wifi_mode, new_wifi_ssid, new_wifi_pass, new_wifi_ap_ssid, new_wifi_ap_pass, true, auth_ips_csv, time_servers_csv, new_mdns_enabled, new_mdns_hostname)) {
    r.code = 500;
    r.body = "{\"ok\":false,\"error\":\"ERR_CONFIG_STATE\",\"detail\":\"failed to persist config\"}";
    return r;
  }

  {
    Preferences mp;
    if (mp.begin("aztcfg", false)) {
      if (new_mqtt_broker_url.length() > 0) kv_set_string(mp, "mqtt_url", new_mqtt_broker_url); else kv_remove_key(mp, "mqtt_url");
      if (new_mqtt_username.length() > 0) kv_set_string(mp, "mqtt_user", new_mqtt_username); else kv_remove_key(mp, "mqtt_user");
      if (new_mqtt_password.length() > 0) kv_set_string(mp, "mqtt_pass", new_mqtt_password); else kv_remove_key(mp, "mqtt_pass");
      if (new_mqtt_audio_rms_topic.length() > 0) kv_set_string(mp, "mqtt_topic", new_mqtt_audio_rms_topic); else kv_remove_key(mp, "mqtt_topic");
      mp.putUShort("mqtt_rms_s", new_mqtt_rms_window_seconds > 0 ? new_mqtt_rms_window_seconds : 10);
      mp.end();
    }
    state.mqtt_broker_url = new_mqtt_broker_url;
    state.mqtt_username = new_mqtt_username;
    state.mqtt_password = new_mqtt_password;
    state.mqtt_audio_rms_topic = new_mqtt_audio_rms_topic;
    state.mqtt_rms_window_seconds = new_mqtt_rms_window_seconds > 0 ? new_mqtt_rms_window_seconds : 10;
  }

  state.discovery_announcement_json = build_discovery_announcement_json(state, kHttpPort);
  Preferences p;
  if (p.begin("aztcfg", false)) {
    kv_set_string(p, "disc_json", state.discovery_announcement_json);
    p.end();
  }

  if (listener_key_changed) {
    request_stream_shutdown();
  }

  if (tls_set) {
    Preferences tp;
    if (tp.begin("aztcfg", false)) {
      bool ok_put = true;
      ok_put = ok_put && kv_set_string(tp, "tls_srv_key", tls_srv_key) > 0;
      ok_put = ok_put && kv_set_string(tp, "tls_srv_cert", tls_srv_cert) > 0;
      if (tls_ca_cert.length() > 0) {
        ok_put = ok_put && kv_set_string(tp, "tls_ca_cert", tls_ca_cert) > 0;
      }
      ok_put = ok_put && kv_set_string(tp, "tls_cert_sn", tls_cert_serial) > 0;
      if (tls_san_csv.length() > 0) {
        ok_put = ok_put && kv_set_string(tp, "tls_san_csv", tls_san_csv) > 0;
      } else {
        kv_remove_key(tp, "tls_san_csv");
      }
      tp.end();
      if (!ok_put) {
        r.code = 500;
        r.body = "{\"ok\":false,\"error\":\"ERR_CONFIG_TLS_STORE\",\"detail\":\"failed to persist tls config\"}";
        return r;
      }
    }
    state.tls_server_key_configured = true;
    state.tls_server_cert_configured = true;
    state.tls_ca_cert_configured = tls_ca_cert.length() > 0;
    state.tls_certificate_serial = tls_cert_serial;
    state.tls_san_hosts_csv = tls_san_csv;
  }

  if (allow_ota_signer_override && (ota_signer_pem.length() > 0 || ota_signer_clear || ota_version_set || ota_floor_set || ota_floor_clear)) {
    Preferences op;
    if (op.begin("aztcfg", false)) {
      if (ota_signer_clear) {
        kv_remove_key(op, "ota_signer_pem");
        kv_remove_key(op, "ota_signer_fp");
        state.ota_signer_override_public_key_pem = "";
        state.ota_signer_override_fingerprint_hex = "";
      } else if (ota_signer_pem.length() > 0) {
        String ota_fp;
        std::vector<uint8_t> ota_pub_raw;
        if (!b64_decode_vec(ota_signer_pem, ota_pub_raw) || ota_pub_raw.size() != crypto_sign_ed25519_PUBLICKEYBYTES) {
          op.end();
          r.code = 400;
          r.body = "{\"ok\":false,\"error\":\"ERR_CONFIG_OTA_SIGNER\",\"detail\":\"invalid ota signer key (expected ed25519 public_key_b64)\"}";
          return r;
        }
        uint8_t h[32] = {0};
        if (!sha256_bytes(ota_pub_raw.data(), ota_pub_raw.size(), h)) {
          op.end();
          r.code = 400;
          r.body = "{\"ok\":false,\"error\":\"ERR_CONFIG_OTA_SIGNER\",\"detail\":\"invalid ota signer hash\"}";
          return r;
        }
        ota_fp = hex_lower(h, sizeof(h));
        kv_set_string(op, "ota_signer_pem", ota_signer_pem);
        kv_set_string(op, "ota_signer_fp", ota_fp);
        state.ota_signer_override_public_key_pem = ota_signer_pem;
        state.ota_signer_override_fingerprint_hex = ota_fp;
      }

      if (ota_floor_clear) {
        kv_remove_key(op, "ota_min_vc");
        kv_remove_key(op, "ota_min_ver_code");
        state.ota_min_allowed_version_code = 0;
      } else if (ota_floor_set) {
        op.putULong64("ota_min_vc", ota_floor_value);
        state.ota_min_allowed_version_code = ota_floor_value;
      }

      op.end();
    }
  }

  r.code = 200;
  r.body = "{\"ok\":true,\"state\":\"MANAGED\",\"signed_config_ready\":true,\"admin_fingerprint_hex\":\"" + state.admin_fingerprint_hex + "\",\"config_revision\":" + String(state.config_revision) + "}";
  if (tls_set) {
    r.reboot_after_response = true;
  }
  return r;
}

static HttpDispatchResult handle_config_patch_json(AppState& state, const String& body) {
  HttpDispatchResult r{};
  r.content_type = "application/json";

  if (!state.managed) {
    r.code = 409;
    r.body = "{\"ok\":false,\"error\":\"ERR_CONFIG_PATCH_UNSET_ADMIN\",\"detail\":\"device is not managed\"}";
    return r;
  }

  JsonDocument doc;
  DeserializationError err = deserializeJson(doc, body);
  if (err) {
    r.code = 400;
    r.body = "{\"ok\":false,\"error\":\"ERR_CONFIG_SCHEMA\",\"detail\":\"invalid json\"}";
    return r;
  }

  int v = doc["config_version"] | 0;
  if (v != 1) {
    r.code = 400;
    r.body = "{\"ok\":false,\"error\":\"ERR_CONFIG_SCHEMA\",\"detail\":\"config_version must be 1\"}";
    return r;
  }

  int if_version = doc["if_version"] | -1;
  if (if_version < 0 || static_cast<uint32_t>(if_version) != state.config_revision) {
    r.code = 409;
    r.body = "{\"ok\":false,\"error\":\"ERR_CONFIG_VERSION_CONFLICT\",\"expected\":" + String(state.config_revision) + ",\"provided\":" + String(if_version) + "}";
    return r;
  }

  if (!doc["admin_key"].isNull() || !doc["ota_signer_public_key_pem"].isNull() || (doc["ota_signer_clear"] | false)) {
    r.code = 403;
    r.body = "{\"ok\":false,\"error\":\"ERR_PATCH_PATH_FORBIDDEN\",\"detail\":\"admin_key/ota_signer cannot be patched over HTTP\"}";
    return r;
  }

  String sig_err;
  if (!verify_config_signature_envelope(doc, state.admin_fingerprint_hex, state.admin_pubkey_pem, sig_err)) {
    r.code = 401;
    r.body = "{\"ok\":false,\"error\":\"ERR_CONFIG_SIGNATURE\",\"detail\":" + json_quote(sig_err) + "}";
    return r;
  }

  JsonVariant patch = doc["patch"];
  if (patch.isNull() || !patch.is<JsonObject>()) {
    r.code = 400;
    r.body = "{\"ok\":false,\"error\":\"ERR_CONFIG_SCHEMA\",\"detail\":\"patch object required\"}";
    return r;
  }

  String new_listener_pem = state.listener_pubkey_pem;
  String new_listener_fp = state.listener_fingerprint_hex;
  String new_recorder_auth_pub = state.recorder_auth_pubkey_b64;
  String new_recorder_auth_fp = state.recorder_auth_fingerprint_hex;
  String new_device_label = state.device_label;
  String new_wifi_mode = state.wifi_mode;
  String new_wifi_ssid = state.wifi_ssid;
  String new_wifi_pass = state.wifi_pass;
  String new_wifi_ap_ssid = state.wifi_ap_ssid;
  String new_wifi_ap_pass = state.wifi_ap_pass;
  String auth_ips_csv = state.authorized_listener_ips_csv;
  String time_servers_csv = state.time_servers_csv;
  bool new_mdns_enabled = state.mdns_enabled;
  String new_mdns_hostname = state.mdns_hostname;
  String new_mqtt_broker_url = state.mqtt_broker_url;
  String new_mqtt_username = state.mqtt_username;
  String new_mqtt_password = state.mqtt_password;
  String new_mqtt_audio_rms_topic = state.mqtt_audio_rms_topic;
  uint16_t new_mqtt_rms_window_seconds = state.mqtt_rms_window_seconds > 0 ? state.mqtt_rms_window_seconds : 10;
  bool new_stream_header_auto_record = state.stream_header_auto_record;
  bool new_stream_header_auto_decode = state.stream_header_auto_decode;
  uint8_t new_audio_preamp_gain = state.audio_preamp_gain;
  uint8_t new_audio_adc_gain = state.audio_adc_gain;

  if (!patch["listener_key"].isNull()) {
    JsonDocument tmp;
    tmp["listener_key"] = patch["listener_key"];
    if (!parse_rsa_key_object(tmp, "listener_key", new_listener_pem, new_listener_fp)) {
      r.code = 400;
      r.body = "{\"ok\":false,\"error\":\"ERR_CONFIG_SCHEMA\",\"detail\":\"invalid listener_key object\"}";
      return r;
    }
  }

  if (!patch["recorder_auth_key"].isNull()) {
    JsonDocument tmp;
    tmp["recorder_auth_key"] = patch["recorder_auth_key"];
    if (!parse_ed25519_key_object(tmp, "recorder_auth_key", new_recorder_auth_pub, new_recorder_auth_fp)) {
      r.code = 400;
      r.body = "{\"ok\":false,\"error\":\"ERR_CONFIG_SCHEMA\",\"detail\":\"invalid recorder_auth_key object\"}";
      return r;
    }
  }

  if (!patch["device_label"].isNull()) {
    new_device_label = String((const char*)(patch["device_label"] | ""));
    new_device_label.trim();
    if (new_device_label.length() == 0) {
      r.code = 400;
      r.body = "{\"ok\":false,\"error\":\"ERR_CONFIG_SCHEMA\",\"detail\":\"device_label cannot be empty\"}";
      return r;
    }
  }

  if (!patch["wifi"].isNull()) {
    if (!parse_wifi_values_variant(patch["wifi"], new_wifi_mode, new_wifi_ssid, new_wifi_pass, new_wifi_ap_ssid, new_wifi_ap_pass)) {
      r.code = 400;
      r.body = "{\"ok\":false,\"error\":\"ERR_CONFIG_SCHEMA\",\"detail\":\"invalid wifi object\"}";
      return r;
    }
  }

  if (!patch["authorized_listener_ips"].isNull()) {
    if (!parse_authorized_listener_ips_variant(patch["authorized_listener_ips"], auth_ips_csv)) {
      r.code = 400;
      r.body = "{\"ok\":false,\"error\":\"ERR_CONFIG_SCHEMA\",\"detail\":\"invalid authorized_listener_ips\"}";
      return r;
    }
  }

  if (!patch["audio"].isNull()) {
    JsonVariant pa = patch["audio"];
    if (!pa.is<JsonObject>()) {
      r.code = 400;
      r.body = "{\"ok\":false,\"error\":\"ERR_CONFIG_SCHEMA\",\"detail\":\"invalid audio object\"}";
      return r;
    }
    if (!pa["preamp_gain"].isNull()) {
      int v = pa["preamp_gain"].as<int>();
      if (v < constants::audio::kPreampGainMin || v > constants::audio::kPreampGainMax) {
        r.code = 400;
        r.body = String("{\"ok\":false,\"error\":\"ERR_CONFIG_SCHEMA\",\"detail\":\"") + constants::audio::kPreampRangeDetail + "\"}";
        return r;
      }
      new_audio_preamp_gain = static_cast<uint8_t>(v);
    }
    if (!pa["adc_gain"].isNull()) {
      int v = pa["adc_gain"].as<int>();
      if (v < constants::audio::kAdcGainMin || v > constants::audio::kAdcGainMax) {
        r.code = 400;
        r.body = String("{\"ok\":false,\"error\":\"ERR_CONFIG_SCHEMA\",\"detail\":\"") + constants::audio::kAdcRangeDetail + "\"}";
        return r;
      }
      new_audio_adc_gain = static_cast<uint8_t>(v);
    }
  }

  if (!patch["time"].isNull()) {
    if (!parse_time_servers_variant(patch["time"], time_servers_csv)) {
      r.code = 400;
      r.body = "{\"ok\":false,\"error\":\"ERR_CONFIG_SCHEMA\",\"detail\":\"invalid time object\"}";
      return r;
    }
  }

  if (!patch["mqtt"].isNull()) {
    JsonVariant pmq = patch["mqtt"];
    if (!pmq.is<JsonObject>()) {
      r.code = 400;
      r.body = "{\"ok\":false,\"error\":\"ERR_CONFIG_SCHEMA\",\"detail\":\"invalid mqtt object\"}";
      return r;
    }
    if (!pmq["broker_url"].isNull()) new_mqtt_broker_url = String((const char*)(pmq["broker_url"] | ""));
    if (!pmq["username"].isNull()) new_mqtt_username = String((const char*)(pmq["username"] | ""));
    if (!pmq["password"].isNull()) new_mqtt_password = String((const char*)(pmq["password"] | ""));
    if (!pmq["audio_rms_topic"].isNull()) new_mqtt_audio_rms_topic = String((const char*)(pmq["audio_rms_topic"] | ""));
    if (!pmq["rms_window_seconds"].isNull()) {
      int v = pmq["rms_window_seconds"].as<int>();
      if (v < 1 || v > 3600) {
        r.code = 400;
        r.body = "{\"ok\":false,\"error\":\"ERR_CONFIG_SCHEMA\",\"detail\":\"invalid mqtt.rms_window_seconds (1..3600)\"}";
        return r;
      }
      new_mqtt_rms_window_seconds = static_cast<uint16_t>(v);
    }
    new_mqtt_broker_url.trim();
    new_mqtt_username.trim();
    new_mqtt_password.trim();
    new_mqtt_audio_rms_topic.trim();
    if (new_mqtt_broker_url.length() > 0 && new_mqtt_audio_rms_topic.length() == 0) {
      r.code = 400;
      r.body = "{\"ok\":false,\"error\":\"ERR_CONFIG_SCHEMA\",\"detail\":\"mqtt.audio_rms_topic required when mqtt.broker_url is set\"}";
      return r;
    }
  }

  if (!patch["stream_header_flags"].isNull()) {
    JsonVariant pshf = patch["stream_header_flags"];
    if (!pshf.is<JsonObject>()) {
      r.code = 400;
      r.body = "{\"ok\":false,\"error\":\"ERR_CONFIG_SCHEMA\",\"detail\":\"invalid stream_header_flags object\"}";
      return r;
    }
    if (!pshf["auto_record"].isNull()) {
      new_stream_header_auto_record = pshf["auto_record"].as<bool>();
    }
    if (!pshf["auto_decode"].isNull()) {
      new_stream_header_auto_decode = pshf["auto_decode"].as<bool>();
    }
  }

  if (!patch["mdns"].isNull()) {
    JsonVariant pm = patch["mdns"];
    if (!pm.is<JsonObject>()) {
      r.code = 400;
      r.body = "{\"ok\":false,\"error\":\"ERR_CONFIG_SCHEMA\",\"detail\":\"invalid mdns object\"}";
      return r;
    }
    new_mdns_enabled = pm["enabled"] | false;
    new_mdns_hostname = String((const char*)(pm["hostname"] | ""));
    new_mdns_hostname.trim();
    new_mdns_hostname.toLowerCase();
    if (!is_valid_mdns_hostname_str(new_mdns_hostname)) {
      r.code = 400;
      r.body = "{\"ok\":false,\"error\":\"ERR_CONFIG_SCHEMA\",\"detail\":\"invalid mdns.hostname\"}";
      return r;
    }
  }

  const bool listener_key_changed =
      (new_listener_pem != state.listener_pubkey_pem) ||
      (new_listener_fp != state.listener_fingerprint_hex);

  state.audio_preamp_gain = new_audio_preamp_gain;
  state.audio_adc_gain = new_audio_adc_gain;
  state.stream_header_auto_record = new_stream_header_auto_record;
  state.stream_header_auto_decode = new_stream_header_auto_decode;
  if (!save_config_state(state,
                         state.admin_pubkey_pem,
                         state.admin_fingerprint_hex,
                         new_listener_pem,
                         new_listener_fp,
                         new_recorder_auth_pub,
                         new_recorder_auth_fp,
                         new_device_label,
                         new_wifi_mode,
                         new_wifi_ssid,
                         new_wifi_pass,
                         new_wifi_ap_ssid,
                         new_wifi_ap_pass,
                         true,
                         auth_ips_csv,
                         time_servers_csv,
                         new_mdns_enabled,
                         new_mdns_hostname)) {
    r.code = 500;
    r.body = "{\"ok\":false,\"error\":\"ERR_CONFIG_STATE\",\"detail\":\"failed to persist config\"}";
    return r;
  }

  {
    Preferences mp;
    if (mp.begin("aztcfg", false)) {
      if (new_mqtt_broker_url.length() > 0) kv_set_string(mp, "mqtt_url", new_mqtt_broker_url); else kv_remove_key(mp, "mqtt_url");
      if (new_mqtt_username.length() > 0) kv_set_string(mp, "mqtt_user", new_mqtt_username); else kv_remove_key(mp, "mqtt_user");
      if (new_mqtt_password.length() > 0) kv_set_string(mp, "mqtt_pass", new_mqtt_password); else kv_remove_key(mp, "mqtt_pass");
      if (new_mqtt_audio_rms_topic.length() > 0) kv_set_string(mp, "mqtt_topic", new_mqtt_audio_rms_topic); else kv_remove_key(mp, "mqtt_topic");
      mp.putUShort("mqtt_rms_s", new_mqtt_rms_window_seconds > 0 ? new_mqtt_rms_window_seconds : 10);
      mp.end();
    }
    state.mqtt_broker_url = new_mqtt_broker_url;
    state.mqtt_username = new_mqtt_username;
    state.mqtt_password = new_mqtt_password;
    state.mqtt_audio_rms_topic = new_mqtt_audio_rms_topic;
    state.mqtt_rms_window_seconds = new_mqtt_rms_window_seconds > 0 ? new_mqtt_rms_window_seconds : 10;
  }

  state.discovery_announcement_json = build_discovery_announcement_json(state, kHttpPort);
  Preferences p;
  if (p.begin("aztcfg", false)) {
    kv_set_string(p, "disc_json", state.discovery_announcement_json);
    p.end();
  }

  if (listener_key_changed) {
    request_stream_shutdown();
  }

  r.code = 200;
  r.body = "{\"ok\":true,\"state\":\"MANAGED\",\"signed_config_ready\":true,\"admin_fingerprint_hex\":\"" + state.admin_fingerprint_hex + "\",\"config_revision\":" + String(state.config_revision) + "}";
  return r;
}

bool parse_request_line(const String& req, String& method, String& path) {
  method = "";
  path = "";

  String s = req;
  s.trim();
  if (s.length() == 0) return false;

  auto is_ws = [&](char c) { return c == ' ' || c == '\t'; };

  int i = 0;
  while (i < static_cast<int>(s.length()) && is_ws(s[i])) i++;
  int m_start = i;
  while (i < static_cast<int>(s.length()) && !is_ws(s[i])) i++;
  int m_end = i;

  while (i < static_cast<int>(s.length()) && is_ws(s[i])) i++;
  int p_start = i;
  while (i < static_cast<int>(s.length()) && !is_ws(s[i])) i++;
  int p_end = i;

  while (i < static_cast<int>(s.length()) && is_ws(s[i])) i++;
  int v_start = i;
  while (i < static_cast<int>(s.length()) && !is_ws(s[i])) i++;
  int v_end = i;

  while (i < static_cast<int>(s.length()) && is_ws(s[i])) i++;

  if (m_end <= m_start || p_end <= p_start || v_end <= v_start) return false;
  if (i != static_cast<int>(s.length())) return false;

  method = s.substring(m_start, m_end);
  path = s.substring(p_start, p_end);
  if (path.length() == 0 || path[0] != '/') return false;

  return true;
}

HttpDispatchResult dispatch_request(const String& method,
                                   const String& path,
                                   const String& body,
                                   AppState& state,
                                   const String& remote_ip) {
  HttpDispatchResult r{};

  if (method == "GET" && path == "/") {
    r.code = 200;
    r.content_type = "text/plain";
    r.body = "Audio Zero Trust device API only\n"
             "api_major=0 api_minor=0 protocol_major=0 protocol_minor=0 container_major=0 container_minor=0\n"
             "Try: /api/v0/capabilities\n";
    return r;
  }

  // Security boundary: before admin key is pinned (managed=false), network API is disabled.
  // Initial claim/bootstrap must happen over serial only.
  if (!state.managed) {
    r.code = 403;
    r.content_type = "application/json";
    r.body = "{\"ok\":false,\"error\":\"ERR_BOOTSTRAP_SERIAL_REQUIRED\",\"detail\":\"network API disabled until admin key is pinned via serial\"}";
    return r;
  }

  if (method == "GET" && path.startsWith("/stream")) {
    r.wants_stream = true;
    r.stream_seconds = parse_seconds_from_path(path);
    r.stream_signbench_each_chunk = parse_signbench_from_path(path);
    r.stream_enable_telemetry = path.indexOf("telemetry=1") >= 0 || path.indexOf("telemetry=true") >= 0 || path.indexOf("telemetry=yes") >= 0 || path.indexOf("telemetry=on") >= 0;
    r.stream_drop_test_frames = parse_drop_test_frames_from_path(path);
    return r;
  }

  if (method == "GET" && path == "/api/v0/device/upgrade") {
    r.code = 200;
    r.content_type = "text/html; charset=utf-8";
    r.body = "<!doctype html><html><head><meta charset=\"utf-8\"><title>AZT OTA Upgrade</title></head><body>"
             "<h1>AZT OTA Upgrade</h1>"
             "<p>POST multipart firmware bundle to <code>/api/v0/device/upgrade</code>.</p>"
             "</body></html>";
    return r;
  }

  if (method == "GET" && path == "/api/v0/device/stream/challenge") {
    (void)issue_single_use_nonce(g_stream_nonce, g_stream_nonce_expires_ms, kStreamNonceTtlMs);
    r.code = 200;
    r.content_type = "application/json";
    r.body = "{\"ok\":true,\"op\":\"stream\",\"nonce\":" + json_quote(g_stream_nonce) +
             ",\"ttl_ms\":" + String(static_cast<unsigned long>(kStreamNonceTtlMs)) +
             ",\"device_sign_fingerprint_hex\":" + json_quote(state.device_sign_fingerprint_hex) +
             ",\"recorder_auth_required\":" + String(state.recorder_auth_pubkey_b64.length() > 0 && state.recorder_auth_fingerprint_hex.length() == 64 ? "true" : "false") + "}";
    return r;
  }

  if (method == "POST" && path == "/api/v0/device/stream/terminate") {
    JsonDocument doc;
    DeserializationError jerr = deserializeJson(doc, body);
    if (jerr) {
      r.code = 400;
      r.content_type = "application/json";
      r.body = "{\"ok\":false,\"error\":\"ERR_STREAM_TERMINATE_SCHEMA\",\"detail\":\"invalid json\"}";
      return r;
    }

    String session_nonce = String((const char*)(doc["stream_auth_nonce"] | ""));
    String sig_alg = String((const char*)(doc["signature_algorithm"] | ""));
    String sig_b64 = String((const char*)(doc["signature_b64"] | ""));
    String signer_fp = String((const char*)(doc["signer_fingerprint_hex"] | ""));
    int reason_code_i = int(doc["reason_code"] | 2);
    if (reason_code_i < 0) reason_code_i = 0;
    if (reason_code_i > 255) reason_code_i = 255;
    uint8_t reason_code = static_cast<uint8_t>(reason_code_i);

    String user_message_json = "{}";
    if (doc["message_json"].is<JsonVariantConst>()) {
      serializeJson(doc["message_json"], user_message_json);
    } else {
      String message_text = String((const char*)(doc["message_text"] | ""));
      JsonDocument fallback;
      fallback["message_text"] = message_text;
      user_message_json = "";
      serializeJson(fallback, user_message_json);
    }

    uint8_t user_msg_hash[32] = {0};
    if (!sha256_bytes(reinterpret_cast<const uint8_t*>(user_message_json.c_str()), user_message_json.length(), user_msg_hash)) {
      r.code = 500;
      r.content_type = "application/json";
      r.body = "{\"ok\":false,\"error\":\"ERR_STREAM_TERMINATE_INTERNAL\",\"detail\":\"message hash failed\"}";
      return r;
    }
    String user_msg_hash_hex = hex_lower(user_msg_hash, sizeof(user_msg_hash));

    String signer_role = "";
    String signer_pubkey = "";
    if (signer_fp == state.recorder_auth_fingerprint_hex &&
        state.recorder_auth_pubkey_b64.length() > 0 &&
        state.recorder_auth_fingerprint_hex.length() == 64) {
      signer_role = "recorder_auth";
      signer_pubkey = state.recorder_auth_pubkey_b64;
    } else if (signer_fp == state.admin_fingerprint_hex &&
               state.admin_pubkey_pem.length() > 0 &&
               state.admin_fingerprint_hex.length() == 64) {
      signer_role = "admin";
      signer_pubkey = state.admin_pubkey_pem;
    }

    if (session_nonce.length() == 0 || sig_alg != "ed25519" || sig_b64.length() == 0 || signer_role.length() == 0) {
      r.code = 401;
      r.content_type = "application/json";
      r.body = "{\"ok\":false,\"error\":\"ERR_STREAM_TERMINATE_AUTH\"}";
      return r;
    }

    String signed_msg = String("stream_terminate:") + session_nonce + ":" + state.device_sign_fingerprint_hex + ":" + String(static_cast<unsigned>(reason_code)) + ":" + user_msg_hash_hex;
    std::vector<uint8_t> msg_raw;
    msg_raw.reserve(signed_msg.length());
    for (size_t i = 0; i < signed_msg.length(); ++i) msg_raw.push_back(static_cast<uint8_t>(signed_msg[i]));

    if (!verify_ed25519_signature_b64(signer_pubkey, msg_raw, sig_b64)) {
      r.code = 401;
      r.content_type = "application/json";
      r.body = "{\"ok\":false,\"error\":\"ERR_STREAM_TERMINATE_AUTH_VERIFY\"}";
      return r;
    }

    JsonDocument emit_msg;
    emit_msg["event"] = "terminate";
    emit_msg["stream_auth_nonce"] = session_nonce;
    emit_msg["reason_code"] = static_cast<unsigned>(reason_code);
    emit_msg["signed_by_fingerprint_hex"] = signer_fp;
    emit_msg["signed_by_role"] = signer_role;
    emit_msg["user_message_sha256_hex"] = user_msg_hash_hex;

    JsonDocument user_doc;
    if (deserializeJson(user_doc, user_message_json) == DeserializationError::Ok) {
      emit_msg["user_message_json"] = user_doc.as<JsonVariantConst>();
    } else {
      emit_msg["user_message_json_raw"] = user_message_json;
    }

    String reason_text;
    serializeJson(emit_msg, reason_text);

    if (!request_stream_termination_by_nonce(session_nonce, reason_code, reason_text)) {
      r.code = 409;
      r.content_type = "application/json";
      r.body = "{\"ok\":false,\"error\":\"ERR_STREAM_SESSION_NOT_ACTIVE\"}";
      return r;
    }

    r.code = 200;
    r.content_type = "application/json";
    r.body = "{\"ok\":true,\"queued\":true,\"stream_auth_nonce\":" + json_quote(session_nonce) +
             ",\"reason_code\":" + String(static_cast<unsigned>(reason_code)) + "}";
    return r;
  }

  if (method == "POST" && path == "/api/v0/config") {
    return handle_config_post_json(state, body, false);
  }

  if (method == "POST" && path == "/api/v0/config/patch") {
    return handle_config_patch_json(state, body);
  }

  if (method == "GET" && path == "/api/v0/device/reboot/challenge") {
    if (!state.managed || state.admin_pubkey_pem.length() == 0 || state.admin_fingerprint_hex.length() != 64) {
      r.code = 409;
      r.content_type = "application/json";
      r.body = "{\"ok\":false,\"error\":\"ERR_REBOOT_AUTH_NOT_READY\"}";
      return r;
    }

    (void)issue_single_use_nonce(g_reboot_nonce, g_reboot_nonce_expires_ms, kRebootNonceTtlMs);

    r.code = 200;
    r.content_type = "application/json";
    r.body = "{\"ok\":true,\"op\":\"reboot\",\"nonce\":" + json_quote(g_reboot_nonce) +
             ",\"ttl_ms\":" + String(static_cast<unsigned long>(kRebootNonceTtlMs)) + "}";
    return r;
  }

  if (method == "GET" && path == "/api/v0/device/ota/wake/challenge") {
    if (!state.managed || state.admin_pubkey_pem.length() == 0 || state.admin_fingerprint_hex.length() != 64) {
      r.code = 409;
      r.content_type = "application/json";
      r.body = "{\"ok\":false,\"error\":\"ERR_OTA_WAKE_AUTH_NOT_READY\"}";
      return r;
    }

    // Issuing a new nonce replaces any previous nonce.
    (void)issue_single_use_nonce(g_ota_wake_nonce, g_ota_wake_nonce_expires_ms, kOtaWakeNonceTtlMs);

    r.code = 200;
    r.content_type = "application/json";
    r.body = "{\"ok\":true,\"op\":\"ota_wake\",\"nonce\":" + json_quote(g_ota_wake_nonce) +
             ",\"ttl_ms\":" + String(static_cast<unsigned long>(kOtaWakeNonceTtlMs)) + "}";
    return r;
  }

  if (method == "POST" && path == "/api/v0/device/ota/wake") {
    if (!state.managed || state.admin_pubkey_pem.length() == 0 || state.admin_fingerprint_hex.length() != 64) {
      r.code = 409;
      r.content_type = "application/json";
      r.body = "{\"ok\":false,\"error\":\"ERR_OTA_WAKE_AUTH_NOT_READY\"}";
      return r;
    }

    JsonDocument doc;
    DeserializationError jerr = deserializeJson(doc, body);
    if (jerr) {
      r.code = 400;
      r.content_type = "application/json";
      r.body = "{\"ok\":false,\"error\":\"ERR_OTA_WAKE_AUTH_SCHEMA\",\"detail\":\"invalid json\"}";
      return r;
    }

    String nonce = String((const char*)(doc["nonce"] | ""));
    String sig_alg = String((const char*)(doc["signature_algorithm"] | ""));
    String sig_b64 = String((const char*)(doc["signature_b64"] | ""));
    String signer_fp = String((const char*)(doc["signer_fingerprint_hex"] | ""));
    bool allow_self = bool(doc["allow_self"] | false);
    String requested_ip = String((const char*)(doc["allowed_ip"] | ""));
    requested_ip.trim();

    uint32_t now_ms = millis();
    if (!validate_active_nonce(nonce, g_ota_wake_nonce, g_ota_wake_nonce_expires_ms, now_ms)) {
      r.code = 401;
      r.content_type = "application/json";
      r.body = "{\"ok\":false,\"error\":\"ERR_OTA_WAKE_CHALLENGE_EXPIRED\"}";
      return r;
    }

    if (sig_alg != "ed25519" || sig_b64.length() == 0 || signer_fp != state.admin_fingerprint_hex) {
      r.code = 401;
      r.content_type = "application/json";
      r.body = "{\"ok\":false,\"error\":\"ERR_OTA_WAKE_AUTH\"}";
      return r;
    }

    String signed_msg = String("ota_wake:") + nonce;
    std::vector<uint8_t> msg_raw;
    msg_raw.reserve(signed_msg.length());
    for (size_t i = 0; i < signed_msg.length(); ++i) msg_raw.push_back(static_cast<uint8_t>(signed_msg[i]));

    if (!verify_ed25519_signature_b64(state.admin_pubkey_pem, msg_raw, sig_b64)) {
      r.code = 401;
      r.content_type = "application/json";
      r.body = "{\"ok\":false,\"error\":\"ERR_OTA_WAKE_AUTH\"}";
      return r;
    }

    String effective_ip = requested_ip;
    if (allow_self) {
      effective_ip = remote_ip;
      // HTTPS peer address may not always surface as plain IPv4; allow explicit allowed_ip fallback.
      IPAddress self_ip_chk;
      if (!self_ip_chk.fromString(effective_ip)) {
        effective_ip = requested_ip;
      }
    }

    IPAddress ip_chk;
    if (!ip_chk.fromString(effective_ip)) {
      r.code = 400;
      r.content_type = "application/json";
      r.body = "{\"ok\":false,\"error\":\"ERR_OTA_WAKE_ALLOWED_IP\",\"detail\":\"valid IPv4 allowed_ip required (or set allow_self=true)\"}";
      return r;
    }

    uint32_t window_ms = kOtaWakeWindowDefaultMs;
    if (!doc["window_seconds"].isNull()) {
      int req_secs = int(doc["window_seconds"] | int(kOtaWakeWindowDefaultMs / 1000));
      if (req_secs < 5) req_secs = 5;
      if (req_secs > 300) req_secs = 300;
      window_ms = static_cast<uint32_t>(req_secs) * 1000U;
    }

    consume_nonce(g_ota_wake_nonce, g_ota_wake_nonce_expires_ms);
    g_ota_wake_allowed_ip = effective_ip;
    g_ota_wake_open_expires_ms = millis() + window_ms;

    r.code = 200;
    r.content_type = "application/json";
    r.body = "{\"ok\":true,\"ota_open\":true,\"allowed_ip\":" + json_quote(g_ota_wake_allowed_ip) +
             ",\"window_ms\":" + String(static_cast<unsigned long>(window_ms)) + "}";
    return r;
  }

  if (method == "POST" && path == "/api/v0/device/reboot") {
    if (!state.managed || state.admin_pubkey_pem.length() == 0 || state.admin_fingerprint_hex.length() != 64) {
      r.code = 409;
      r.content_type = "application/json";
      r.body = "{\"ok\":false,\"error\":\"ERR_REBOOT_AUTH_NOT_READY\"}";
      return r;
    }

    JsonDocument doc;
    DeserializationError jerr = deserializeJson(doc, body);
    if (jerr) {
      r.code = 400;
      r.content_type = "application/json";
      r.body = "{\"ok\":false,\"error\":\"ERR_REBOOT_AUTH_SCHEMA\",\"detail\":\"invalid json\"}";
      return r;
    }

    String nonce = String((const char*)(doc["nonce"] | ""));
    String sig_alg = String((const char*)(doc["signature_algorithm"] | ""));
    String sig_b64 = String((const char*)(doc["signature_b64"] | ""));
    String signer_fp = String((const char*)(doc["signer_fingerprint_hex"] | ""));

    uint32_t now_ms = millis();
    if (!validate_active_nonce(nonce, g_reboot_nonce, g_reboot_nonce_expires_ms, now_ms)) {
      r.code = 401;
      r.content_type = "application/json";
      r.body = "{\"ok\":false,\"error\":\"ERR_REBOOT_CHALLENGE_EXPIRED\"}";
      return r;
    }

    if (sig_alg != "ed25519" || sig_b64.length() == 0 || signer_fp != state.admin_fingerprint_hex) {
      r.code = 401;
      r.content_type = "application/json";
      r.body = "{\"ok\":false,\"error\":\"ERR_REBOOT_AUTH\"}";
      return r;
    }

    String signed_msg = String("reboot:") + nonce;
    std::vector<uint8_t> msg_raw;
    msg_raw.reserve(signed_msg.length());
    for (size_t i = 0; i < signed_msg.length(); ++i) msg_raw.push_back(static_cast<uint8_t>(signed_msg[i]));

    if (!verify_ed25519_signature_b64(state.admin_pubkey_pem, msg_raw, sig_b64)) {
      r.code = 401;
      r.content_type = "application/json";
      r.body = "{\"ok\":false,\"error\":\"ERR_REBOOT_SIG_VERIFY\"}";
      return r;
    }

    // Consume nonce on first successful use (single-use challenge).
    consume_nonce(g_reboot_nonce, g_reboot_nonce_expires_ms);

    r.code = 200;
    r.content_type = "application/json";
    r.body = "{\"ok\":true,\"rebooting\":true}";
    r.reboot_after_response = true;
    return r;
  }

  if (method == "GET" && path.startsWith("/api/v0/device/attestation")) {
    String nonce = parse_query_param(path, "nonce");
    if (!is_valid_attestation_nonce(nonce)) {
      r.code = 400;
      r.body = "{\"ok\":false,\"error\":\"ERR_ATTEST_NONCE\",\"detail\":\"nonce required (8..256 chars, [A-Za-z0-9._-])\"}";
      r.content_type = "application/json";
      return r;
    }

    unsigned char sign_sk[crypto_sign_ed25519_SECRETKEYBYTES] = {0};
    if (sodium_init() < 0 || !load_device_sign_sk(sign_sk)) {
      r.code = 500;
      r.body = "{\"ok\":false,\"error\":\"ERR_ATTEST_SIGN_KEY\",\"detail\":\"device signing key unavailable\"}";
      r.content_type = "application/json";
      return r;
    }

    String payload = "{";
    payload += "\"attestation_version\":1,";
    payload += "\"attestation_type\":\"device_key_ownership\",";
    payload += "\"nonce\":\"" + nonce + "\",";
    payload += "\"device_sign_public_key_b64\":\"" + state.device_sign_public_key_b64 + "\",";
    payload += "\"device_sign_fingerprint_hex\":\"" + state.device_sign_fingerprint_hex + "\",";
    payload += "\"device_chip_id_hex\":\"" + state.device_chip_id_hex + "\",";
    payload += "\"listener_public_key_pem\":" + json_quote(state.listener_pubkey_pem) + ",";
    payload += "\"listener_fingerprint_hex\":\"" + state.listener_fingerprint_hex + "\"";
    payload += "}";

    unsigned char sig[crypto_sign_ed25519_BYTES] = {0};
    unsigned long long sig_len = 0;
    if (crypto_sign_ed25519_detached(sig,
                                     &sig_len,
                                     reinterpret_cast<const unsigned char*>(payload.c_str()),
                                     payload.length(),
                                     sign_sk) != 0 ||
        sig_len != crypto_sign_ed25519_BYTES) {
      r.code = 500;
      r.body = "{\"ok\":false,\"error\":\"ERR_ATTEST_SIGN\",\"detail\":\"failed to sign attestation\"}";
      r.content_type = "application/json";
      return r;
    }

    r.code = 200;
    r.body = "{\"ok\":true,\"payload\":" + payload +
             ",\"signature_algorithm\":\"ed25519\",\"signature_b64\":\"" +
             b64(sig, crypto_sign_ed25519_BYTES) + "\"}";
    r.content_type = "application/json";
    return r;
  }

  if (method == "GET" && path == "/api/v0/device/certificate") {
    Preferences p;
    if (!p.begin("aztcfg", true)) {
      r.code = 500;
      r.body = "{\"ok\":false,\"error\":\"ERR_CERT_STORE\"}";
      r.content_type = "application/json";
      return r;
    }
    String cert_json = kv_get_string(p, "device_cert", "");
    p.end();
    if (cert_json.length() == 0) {
      r.code = 404;
      r.body = "{\"ok\":false,\"error\":\"ERR_CERT_NOT_FOUND\"}";
      r.content_type = "application/json";
      return r;
    }
    r.code = 200;
    r.body = "{\"ok\":true,\"certificate\":" + cert_json + "}";
    r.content_type = "application/json";
    return r;
  }

  if (method == "GET" && path == "/api/v0/device/certificate/challenge") {
    if (!state.managed || state.admin_pubkey_pem.length() == 0 || state.admin_fingerprint_hex.length() != 64) {
      r.code = 409;
      r.content_type = "application/json";
      r.body = "{\"ok\":false,\"error\":\"ERR_CERT_AUTH_NOT_READY\"}";
      return r;
    }
    (void)issue_single_use_nonce(g_cert_nonce, g_cert_nonce_expires_ms, kRebootNonceTtlMs);
    r.code = 200;
    r.content_type = "application/json";
    r.body = "{\"ok\":true,\"op\":\"device_certificate\",\"nonce\":" + json_quote(g_cert_nonce) +
             ",\"ttl_ms\":" + String(static_cast<unsigned long>(kRebootNonceTtlMs)) + "}";
    return r;
  }

  if (method == "POST" && path == "/api/v0/device/certificate") {
    JsonDocument doc;
    DeserializationError err = deserializeJson(doc, body);
    if (err) {
      r.code = 400;
      r.body = "{\"ok\":false,\"error\":\"ERR_CERT_SCHEMA\",\"detail\":\"invalid json\"}";
      r.content_type = "application/json";
      return r;
    }

    String payload_b64 = String((const char*)(doc["certificate_payload_b64"] | ""));
    String sig_alg = String((const char*)(doc["signature_algorithm"] | ""));
    String sig_b64 = String((const char*)(doc["signature_b64"] | ""));
    if (payload_b64.length() == 0 || sig_b64.length() == 0 || sig_alg != "ed25519") {
      r.code = 400;
      r.body = "{\"ok\":false,\"error\":\"ERR_CERT_SCHEMA\",\"detail\":\"missing certificate_payload_b64/signature fields\"}";
      r.content_type = "application/json";
      return r;
    }

    std::vector<uint8_t> payload_raw;
    if (!b64_decode_vec(payload_b64, payload_raw) || payload_raw.empty()) {
      r.code = 400;
      r.body = "{\"ok\":false,\"error\":\"ERR_CERT_PAYLOAD_B64\"}";
      r.content_type = "application/json";
      return r;
    }

    JsonDocument payload_doc;
    DeserializationError perr = deserializeJson(payload_doc, payload_raw.data(), payload_raw.size());
    if (perr) {
      r.code = 400;
      r.body = "{\"ok\":false,\"error\":\"ERR_CERT_PAYLOAD_JSON\"}";
      r.content_type = "application/json";
      return r;
    }

    String cert_type = String((const char*)(payload_doc["certificate_type"] | "device_key_binding"));
    String dev_pub = String((const char*)(payload_doc["device_sign_public_key_b64"] | ""));
    String dev_fp = String((const char*)(payload_doc["device_sign_fingerprint_hex"] | ""));
    String chip_id = String((const char*)(payload_doc["device_chip_id_hex"] | ""));
    String rec_pub = String((const char*)(payload_doc["listener_public_key_pem"] | ""));
    if (rec_pub.length() == 0) rec_pub = String((const char*)(payload_doc["listener_public_key_pem"] | ""));
    String rec_fp = String((const char*)(payload_doc["listener_fingerprint_hex"] | ""));
    if (rec_fp.length() == 0) rec_fp = String((const char*)(payload_doc["listener_fingerprint_hex"] | ""));
    String admin_fp = String((const char*)(payload_doc["admin_signer_fingerprint_hex"] | ""));
    String cert_serial = String((const char*)(payload_doc["certificate_serial"] | ""));
    String cert_nonce = String((const char*)(payload_doc["nonce"] | ""));

    uint32_t cert_now_ms = millis();
    if (!validate_active_nonce(cert_nonce, g_cert_nonce, g_cert_nonce_expires_ms, cert_now_ms)) {
      r.code = 401;
      r.body = "{\"ok\":false,\"error\":\"ERR_CERT_CHALLENGE_EXPIRED\"}";
      r.content_type = "application/json";
      return r;
    }

    if (cert_type == "device_key_revocation") {
      if (state.admin_pubkey_pem.length() == 0 || state.admin_fingerprint_hex.length() != 64) {
        r.code = 500;
        r.body = "{\"ok\":false,\"error\":\"ERR_CERT_ADMIN_NOT_CONFIGURED\"}";
        r.content_type = "application/json";
        return r;
      }
      if (admin_fp != state.admin_fingerprint_hex) {
        r.code = 401;
        r.body = "{\"ok\":false,\"error\":\"ERR_CERT_ADMIN_MISMATCH\"}";
        r.content_type = "application/json";
        return r;
      }
      if (!verify_ed25519_signature_b64(state.admin_pubkey_pem, payload_raw, sig_b64)) {
        r.code = 401;
        r.body = "{\"ok\":false,\"error\":\"ERR_CERT_SIG_VERIFY\"}";
        r.content_type = "application/json";
        return r;
      }
      if (cert_serial.length() > 0 && state.device_certificate_serial.length() > 0 && cert_serial != state.device_certificate_serial) {
        r.code = 409;
        r.body = "{\"ok\":false,\"error\":\"ERR_CERT_SERIAL_MISMATCH\"}";
        r.content_type = "application/json";
        return r;
      }

      state.device_certificate_serial = "";
      state.device_certificate_json = "";
      state.discovery_announcement_json = build_discovery_announcement_json(state, kHttpPort);

      Preferences p;
      if (!p.begin("aztcfg", false) || kv_set_string(p, "disc_json", state.discovery_announcement_json) == 0) {
        p.end();
        r.code = 500;
        r.body = "{\"ok\":false,\"error\":\"ERR_CERT_STORE\"}";
        r.content_type = "application/json";
        return r;
      }
      kv_remove_key(p, "device_cert");
      kv_remove_key(p, "dev_cert_sn");
      p.end();

      consume_nonce(g_cert_nonce, g_cert_nonce_expires_ms);

      r.code = 200;
      r.body = "{\"ok\":true,\"revoked\":true}";
      r.content_type = "application/json";
      return r;
    }

    if (dev_pub != state.device_sign_public_key_b64 || dev_fp != state.device_sign_fingerprint_hex || chip_id != state.device_chip_id_hex) {
      r.code = 400;
      r.body = "{\"ok\":false,\"error\":\"ERR_CERT_DEVICE_MISMATCH\"}";
      r.content_type = "application/json";
      return r;
    }
    if (rec_pub != state.listener_pubkey_pem || rec_fp != state.listener_fingerprint_hex) {
      r.code = 400;
      r.body = "{\"ok\":false,\"error\":\"ERR_CERT_RECORDER_MISMATCH\"}";
      r.content_type = "application/json";
      return r;
    }
    if (admin_fp != state.admin_fingerprint_hex) {
      r.code = 401;
      r.body = "{\"ok\":false,\"error\":\"ERR_CERT_ADMIN_MISMATCH\"}";
      r.content_type = "application/json";
      return r;
    }
    if (state.admin_pubkey_pem.length() == 0 || state.admin_fingerprint_hex.length() != 64) {
      r.code = 500;
      r.body = "{\"ok\":false,\"error\":\"ERR_CERT_ADMIN_NOT_CONFIGURED\"}";
      r.content_type = "application/json";
      return r;
    }

    std::vector<uint8_t> admin_pub_raw;
    if (!b64_decode_vec(state.admin_pubkey_pem, admin_pub_raw) || admin_pub_raw.size() != crypto_sign_ed25519_PUBLICKEYBYTES) {
      r.code = 400;
      r.body = "{\"ok\":false,\"error\":\"ERR_CERT_ADMIN_FP\"}";
      r.content_type = "application/json";
      return r;
    }
    uint8_t admin_h[32] = {0};
    if (!sha256_bytes(admin_pub_raw.data(), admin_pub_raw.size(), admin_h) || hex_lower(admin_h, sizeof(admin_h)) != admin_fp) {
      r.code = 400;
      r.body = "{\"ok\":false,\"error\":\"ERR_CERT_ADMIN_FP\"}";
      r.content_type = "application/json";
      return r;
    }

    if (!verify_ed25519_signature_b64(state.admin_pubkey_pem, payload_raw, sig_b64)) {
      r.code = 401;
      r.body = "{\"ok\":false,\"error\":\"ERR_CERT_SIG_VERIFY\"}";
      r.content_type = "application/json";
      return r;
    }

    // Preserve the third-party certificate envelope verbatim as received.
    String cert_json = body;

    state.device_certificate_serial = cert_serial;
    state.device_certificate_json = cert_json;
    state.discovery_announcement_json = build_discovery_announcement_json(state, kHttpPort);

    Preferences p;
    if (!p.begin("aztcfg", false) ||
        kv_set_string(p, "device_cert", cert_json) == 0 ||
        kv_set_string(p, "dev_cert_sn", cert_serial) == 0 ||
        kv_set_string(p, "disc_json", state.discovery_announcement_json) == 0) {
      p.end();
      r.code = 500;
      r.body = "{\"ok\":false,\"error\":\"ERR_CERT_STORE\"}";
      r.content_type = "application/json";
      return r;
    }
    p.end();

    consume_nonce(g_cert_nonce, g_cert_nonce_expires_ms);

    r.code = 200;
    r.body = "{\"ok\":true,\"stored\":true,\"certificate_serial\":\"" + cert_serial + "\"}";
    r.content_type = "application/json";
    return r;
  }

  if (method == "GET" && path == "/api/v0/tls/csr") {
    String pem;
    if (!ed25519_pub_raw_to_spki_pem(state.device_sign_public_key_b64, pem)) {
      r.code = 500;
      r.body = "{\"ok\":false,\"error\":\"ERR_TLS_CSR_KEY\"}";
      r.content_type = "application/json";
      return r;
    }
    r.code = 200;
    r.body = "{\"ok\":true,\"csr_version\":1,\"csr_kind\":\"device_signing_key_binding\",\"device_sign_public_key_b64\":" + json_quote(state.device_sign_public_key_b64) +
             ",\"device_sign_fingerprint_hex\":" + json_quote(state.device_sign_fingerprint_hex) +
             ",\"device_chip_id_hex\":" + json_quote(state.device_chip_id_hex) +
             ",\"public_key_pem\":" + json_quote(pem) + "}";
    r.content_type = "application/json";
    return r;
  }

  if (method == "GET" && path == "/api/v0/tls/state") {
    r.code = 200;
    r.body = "{\"ok\":true,\"tls_server_cert_configured\":" + String(state.tls_server_cert_configured ? "true" : "false") +
             ",\"tls_server_key_configured\":" + String(state.tls_server_key_configured ? "true" : "false") +
             ",\"tls_ca_cert_configured\":" + String(state.tls_ca_cert_configured ? "true" : "false") +
             ",\"tls_certificate_serial\":" + json_quote(state.tls_certificate_serial) +
             ",\"tls_san_hosts_csv\":" + json_quote(state.tls_san_hosts_csv) + "}";
    r.content_type = "application/json";
    return r;
  }

  if (method == "GET" && path == "/api/v0/tls/cert/challenge") {
    if (!state.managed || state.admin_pubkey_pem.length() == 0 || state.admin_fingerprint_hex.length() != 64) {
      r.code = 409;
      r.content_type = "application/json";
      r.body = "{\"ok\":false,\"error\":\"ERR_TLS_AUTH_NOT_READY\"}";
      return r;
    }
    (void)issue_single_use_nonce(g_tls_cert_nonce, g_tls_cert_nonce_expires_ms, kRebootNonceTtlMs);
    r.code = 200;
    r.content_type = "application/json";
    r.body = "{\"ok\":true,\"op\":\"tls_cert\",\"nonce\":" + json_quote(g_tls_cert_nonce) +
             ",\"ttl_ms\":" + String(static_cast<unsigned long>(kRebootNonceTtlMs)) + "}";
    return r;
  }

  if (method == "POST" && path == "/api/v0/tls/cert") {
    if (state.admin_pubkey_pem.length() == 0 || state.admin_fingerprint_hex.length() != 64) {
      r.code = 500;
      r.body = "{\"ok\":false,\"error\":\"ERR_TLS_ADMIN_NOT_CONFIGURED\"}";
      r.content_type = "application/json";
      return r;
    }

    JsonDocument doc;
    DeserializationError err = deserializeJson(doc, body);
    if (err) {
      r.code = 400;
      r.body = "{\"ok\":false,\"error\":\"ERR_TLS_SCHEMA\",\"detail\":\"invalid json\"}";
      r.content_type = "application/json";
      return r;
    }

    String payload_b64 = String((const char*)(doc["tls_payload_b64"] | ""));
    String sig_alg = String((const char*)(doc["signature_algorithm"] | ""));
    String sig_b64 = String((const char*)(doc["signature_b64"] | ""));
    if (payload_b64.length() == 0 || sig_b64.length() == 0 || sig_alg != "ed25519") {
      r.code = 400;
      r.body = "{\"ok\":false,\"error\":\"ERR_TLS_SCHEMA\",\"detail\":\"missing tls_payload_b64/signature fields\"}";
      r.content_type = "application/json";
      return r;
    }

    std::vector<uint8_t> payload_raw;
    if (!b64_decode_vec(payload_b64, payload_raw) || payload_raw.empty()) {
      r.code = 400;
      r.body = "{\"ok\":false,\"error\":\"ERR_TLS_PAYLOAD_B64\"}";
      r.content_type = "application/json";
      return r;
    }

    JsonDocument payload_doc;
    if (deserializeJson(payload_doc, payload_raw.data(), payload_raw.size())) {
      r.code = 400;
      r.body = "{\"ok\":false,\"error\":\"ERR_TLS_PAYLOAD_JSON\"}";
      r.content_type = "application/json";
      return r;
    }

    String dev_fp = String((const char*)(payload_doc["device_sign_fingerprint_hex"] | ""));
    String chip_id = String((const char*)(payload_doc["device_chip_id_hex"] | ""));
    String admin_fp = String((const char*)(payload_doc["admin_signer_fingerprint_hex"] | ""));
    String cert_serial = String((const char*)(payload_doc["tls_certificate_serial"] | ""));
    String tls_srv_cert = String((const char*)(payload_doc["tls_server_certificate_pem"] | ""));
    String tls_srv_key = String((const char*)(payload_doc["tls_server_private_key_pem"] | ""));
    String tls_ca_cert = String((const char*)(payload_doc["tls_ca_certificate_pem"] | ""));
    String tls_nonce = String((const char*)(payload_doc["nonce"] | ""));

    uint32_t tls_now_ms = millis();
    if (!validate_active_nonce(tls_nonce, g_tls_cert_nonce, g_tls_cert_nonce_expires_ms, tls_now_ms)) {
      r.code = 401;
      r.body = "{\"ok\":false,\"error\":\"ERR_TLS_CHALLENGE_EXPIRED\"}";
      r.content_type = "application/json";
      return r;
    }

    if (dev_fp != state.device_sign_fingerprint_hex || chip_id != state.device_chip_id_hex || admin_fp != state.admin_fingerprint_hex) {
      r.code = 401;
      r.body = "{\"ok\":false,\"error\":\"ERR_TLS_IDENTITY_MISMATCH\"}";
      r.content_type = "application/json";
      return r;
    }
    if (cert_serial.length() == 0 || tls_srv_cert.length() == 0 || tls_srv_key.length() == 0) {
      r.code = 400;
      r.body = "{\"ok\":false,\"error\":\"ERR_TLS_SCHEMA\",\"detail\":\"missing tls cert serial/server certificate/private key\"}";
      r.content_type = "application/json";
      return r;
    }

    if (!verify_ed25519_signature_b64(state.admin_pubkey_pem, payload_raw, sig_b64)) {
      r.code = 401;
      r.body = "{\"ok\":false,\"error\":\"ERR_TLS_SIG_VERIFY\"}";
      r.content_type = "application/json";
      return r;
    }

    Preferences p;
    if (!p.begin("aztcfg", false)) {
      r.code = 500;
      r.body = "{\"ok\":false,\"error\":\"ERR_TLS_STORE\"}";
      r.content_type = "application/json";
      return r;
    }
    bool ok_put = true;
    ok_put = ok_put && kv_set_string(p, "tls_srv_key", tls_srv_key) > 0;
    ok_put = ok_put && kv_set_string(p, "tls_srv_cert", tls_srv_cert) > 0;
    if (tls_ca_cert.length() > 0) {
      ok_put = ok_put && kv_set_string(p, "tls_ca_cert", tls_ca_cert) > 0;
    }
    ok_put = ok_put && kv_set_string(p, "tls_cert_sn", cert_serial) > 0;
    p.end();

    if (!ok_put) {
      r.code = 500;
      r.body = "{\"ok\":false,\"error\":\"ERR_TLS_STORE\"}";
      r.content_type = "application/json";
      return r;
    }

    state.tls_server_key_configured = true;
    state.tls_server_cert_configured = true;
    state.tls_ca_cert_configured = tls_ca_cert.length() > 0;
    state.tls_certificate_serial = cert_serial;

    consume_nonce(g_tls_cert_nonce, g_tls_cert_nonce_expires_ms);

    r.code = 200;
    r.body = "{\"ok\":true,\"stored\":true,\"tls_certificate_serial\":" + json_quote(cert_serial) + "}";
    r.content_type = "application/json";
    return r;
  }

  if (method == "GET" && path == "/api/v0/capabilities") {
    r.code = 200;
    r.body = "{\"ok\":true,\"api_major\":0,\"api_minor\":0,\"protocol_major\":0,\"protocol_minor\":0,\"container_major\":0,\"container_minor\":0,\"supported_features\":[\"config\",\"config_patch\",\"attestation\",\"certificate\",\"ota_upgrade\",\"stream\",\"tls\"]}";
    r.content_type = "application/json";
    return r;
  }

  if (method == "GET" && path == "/api/v0/config/state") {
    String status = !state.managed ? "UNSET_ADMIN" : (state.signed_config_ready ? "MANAGED" : "PENDING_SIGNED_CONFIG");
    bool wifi_cfg = (state.wifi_mode == "ap") ? (state.wifi_ap_ssid.length() > 0 && state.wifi_ap_pass.length() >= 8) : (state.wifi_ssid.length() > 0 && state.wifi_pass.length() > 0);
    bool listener_key_cfg = state.listener_pubkey_pem.length() > 0 && state.listener_fingerprint_hex.length() == 64;
    String ota_active_pem = state.ota_signer_override_public_key_pem.length() > 0 ? state.ota_signer_override_public_key_pem : String(kOtaSignerPublicKeyPem);
    String ota_active_fp;
    std::vector<uint8_t> ota_active_pub;
    if (b64_decode_vec(ota_active_pem, ota_active_pub) && ota_active_pub.size() == crypto_sign_ed25519_PUBLICKEYBYTES) {
      uint8_t h[32] = {0};
      if (sha256_bytes(ota_active_pub.data(), ota_active_pub.size(), h)) ota_active_fp = hex_lower(h, sizeof(h));
    }
    String ota_source = state.ota_signer_override_public_key_pem.length() > 0 ? "serial_override" : "default_embedded";

    time_t now_epoch = time(nullptr);
    if (now_epoch < 0) now_epoch = 0;
    String now_utc = "";
    if (now_epoch > 0) {
      struct tm tm_utc;
      gmtime_r(&now_epoch, &tm_utc);
      char buf[32] = {0};
      strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tm_utc);
      now_utc = String(buf);
    }
    long time_staleness_s = -1;
    if (state.time_last_sync_epoch > 0 && now_epoch >= static_cast<time_t>(state.time_last_sync_epoch)) {
      time_staleness_s = static_cast<long>(now_epoch - static_cast<time_t>(state.time_last_sync_epoch));
    }
    r.code = 200;
    r.body = "{\"ok\":true,\"api_major\":0,\"api_minor\":0,\"protocol_major\":0,\"protocol_minor\":0,\"container_major\":0,\"container_minor\":0,\"state\":\"" + status +
             "\",\"signed_config_ready\":" +
             String(state.signed_config_ready ? "true" : "false") +
             ",\"device_label\":\"" + state.device_label +
             "\",\"wifi_configured\":" + String(wifi_cfg ? "true" : "false") +
             ",\"wifi_ssid\":\"" + state.wifi_ssid +
             "\",\"wifi_last_connect_source\":\"" + state.wifi_last_connect_source +
             "\",\"wifi_last_status\":" + String(state.wifi_last_status) +
             ",\"audio_input_source\":" + json_quote(state.audio_input_source) +
             ",\"audio_echo_base_detected\":" + String(state.audio_echo_base_detected ? "true" : "false") +
             ",\"audio_preamp_gain\":" + String(state.audio_preamp_gain) +
             ",\"audio_adc_gain\":" + String(state.audio_adc_gain) +
             ",\"audio_codec_probe_attempts\":" + String(state.audio_codec_probe_attempts) +
             ",\"audio_codec_probe_success_attempt\":" + String(state.audio_codec_probe_success_attempt) +
             ",\"audio_codec_probe_round\":" + String(state.audio_codec_probe_round) +
             ",\"audio_codec_probe_last_millis\":" + String(state.audio_codec_probe_last_millis) +
             ",\"authorized_listener_ips_csv\":\"" + state.authorized_listener_ips_csv +
             "\",\"time_servers_csv\":\"" + state.time_servers_csv +
             "\",\"device_certificate_serial\":\"" + state.device_certificate_serial +
             "\",\"tls_server_cert_configured\":" + String(state.tls_server_cert_configured ? "true" : "false") +
             ",\"tls_server_key_configured\":" + String(state.tls_server_key_configured ? "true" : "false") +
             ",\"tls_ca_cert_configured\":" + String(state.tls_ca_cert_configured ? "true" : "false") +
             ",\"tls_certificate_serial\":\"" + state.tls_certificate_serial +
             "\",\"tls_san_hosts_csv\":" + json_quote(state.tls_san_hosts_csv) +
             ",\"admin_fingerprint_hex\":\"" + state.admin_fingerprint_hex +
             "\",\"listener_key_configured\":" + String(listener_key_cfg ? "true" : "false") +
             ",\"listener_public_key_pem\":" + json_quote(state.listener_pubkey_pem) +
             ",\"listener_fingerprint_hex\":\"" + state.listener_fingerprint_hex +
             "\",\"listener_key_alg\":\"rsa-oaep-sha256\"" +
             ",\"recorder_auth_key_configured\":" + String(state.recorder_auth_pubkey_b64.length() > 0 && state.recorder_auth_fingerprint_hex.length() == 64 ? "true" : "false") +
             ",\"recorder_auth_public_key_b64\":" + json_quote(state.recorder_auth_pubkey_b64) +
             ",\"recorder_auth_fingerprint_hex\":\"" + state.recorder_auth_fingerprint_hex + "\"" +
             ",\"stream_header_auto_record\":" + String(state.stream_header_auto_record ? "true" : "false") +
             ",\"stream_header_auto_decode\":" + String(state.stream_header_auto_decode ? "true" : "false") +
             ",\"device_sign_alg\":\"ed25519\"" +
             ",\"firmware_build_number\":\"" + String(AZT_STR(AZT_BUILD_NUMBER)) +
             "\",\"firmware_build_id\":\"" + String(AZT_STR(AZT_BUILD_ID)) +
             "\",\"ota_signer_source\":\"" + ota_source +
             "\",\"ota_signer_fingerprint_hex\":\"" + ota_active_fp +
             "\",\"last_ota_version\":\"" + state.last_ota_version +
             "\",\"last_ota_version_code\":" + String(static_cast<unsigned long long>(state.last_ota_version_code)) +
             ",\"ota_min_allowed_version_code\":" + String(static_cast<unsigned long long>(state.ota_min_allowed_version_code)) +
             ",\"device_time_epoch\":" + String(static_cast<unsigned long>(now_epoch)) +
             ",\"device_time_utc\":\"" + now_utc +
             "\",\"time_synced\":" + String(state.time_synced ? "true" : "false") +
             ",\"time_last_sync_epoch\":" + String(state.time_last_sync_epoch) +
             ",\"time_server_staleness_s\":" + String(time_staleness_s) +
             ",\"mdns_enabled\":" + String(state.mdns_enabled ? "true" : "false") +
             ",\"mdns_hostname\":\"" + state.mdns_hostname +
             "\",\"mdns_fqdn\":\"" + (state.mdns_hostname.length() > 0 ? state.mdns_hostname + ".local" : String("")) +
             "\",\"mqtt_configured\":" + String(state.mqtt_broker_url.length() > 0 ? "true" : "false") +
             ",\"mqtt_broker_url\":" + json_quote(state.mqtt_broker_url) +
             ",\"mqtt_audio_rms_topic\":" + json_quote(state.mqtt_audio_rms_topic) +
             ",\"mqtt_rms_window_seconds\":" + String(state.mqtt_rms_window_seconds > 0 ? state.mqtt_rms_window_seconds : 10) +
             ",\"device_sign_public_key_b64\":\"" + state.device_sign_public_key_b64 +
             "\",\"device_sign_fingerprint_hex\":\"" + state.device_sign_fingerprint_hex +
             "\",\"device_chip_id_hex\":\"" + state.device_chip_id_hex +
             "\",\"last_reset_reason\":\"" + state.last_reset_reason +
             "\",\"last_reset_reason_code\":" + String(state.last_reset_reason_code) +
             ",\"last_reset_unexpected\":" + String(state.last_reset_unexpected ? "true" : "false") +
             ",\"unexpected_reset_count\":" + String(state.unexpected_reset_count) +
             ",\"config_revision\":" + String(state.config_revision) + "}";
    r.content_type = "application/json";
    return r;
  }

  if (method == "GET" && (path == "/api/v0/device/signing-public-key.pem" || path == "/api/v0/device/signing-public-key")) {
    String pem;
    if (!ed25519_pub_raw_to_spki_pem(state.device_sign_public_key_b64, pem)) {
      r.code = 500;
      r.body = "failed to build signing public key PEM\n";
      r.content_type = "text/plain";
      return r;
    }
    r.code = 200;
    r.body = pem;
    r.content_type = "application/x-pem-file";
    return r;
  }

  r.code = 404;
  r.body = "not found\n";
  r.content_type = "text/plain";
  return r;
}

HttpDispatchResult apply_config_json_from_serial(AppState& state, const String& body) {
  return handle_config_post_json(state, body, true);
}

HttpDispatchResult apply_ota_controls_json_from_serial(AppState& state, const String& body) {
  HttpDispatchResult r{};
  r.content_type = "application/json";

  JsonDocument doc;
  DeserializationError err = deserializeJson(doc, body);
  if (err) {
    r.code = 400;
    r.body = "{\"ok\":false,\"error\":\"ERR_CONFIG_SCHEMA\",\"detail\":\"invalid json\"}";
    return r;
  }

  String ota_signer_pem = String((const char*)(doc["ota_signer_public_key_pem"] | ""));
  ota_signer_pem.trim();
  bool ota_signer_clear = doc["ota_signer_clear"] | false;

  bool ota_version_set = !doc["ota_version_code"].isNull();
  uint64_t ota_version_value = 0;
  bool ota_floor_set = !doc["ota_min_allowed_version_code"].isNull();
  bool ota_floor_clear = doc["ota_min_allowed_version_code_clear"] | false;
  uint64_t ota_floor_value = 0;

  if (ota_version_set) {
    JsonVariantConst vv = doc["ota_version_code"];
    if (vv.is<uint64_t>()) {
      ota_version_value = vv.as<uint64_t>();
    } else if (vv.is<unsigned long>()) {
      ota_version_value = static_cast<uint64_t>(vv.as<unsigned long>());
    } else if (vv.is<const char*>()) {
      const char* s = vv.as<const char*>();
      char* end = nullptr;
      unsigned long long parsed = strtoull(s ? s : "", &end, 10);
      if (!end || *end != '\0') {
        r.code = 400;
        r.body = "{\"ok\":false,\"error\":\"ERR_CONFIG_SCHEMA\",\"detail\":\"invalid ota_version_code\"}";
        return r;
      }
      ota_version_value = static_cast<uint64_t>(parsed);
    } else {
      r.code = 400;
      r.body = "{\"ok\":false,\"error\":\"ERR_CONFIG_SCHEMA\",\"detail\":\"invalid ota_version_code\"}";
      return r;
    }
    if (ota_version_value == 0) {
      r.code = 400;
      r.body = "{\"ok\":false,\"error\":\"ERR_CONFIG_SCHEMA\",\"detail\":\"ota_version_code must be > 0\"}";
      return r;
    }
  }

  if (ota_floor_set) {
    JsonVariantConst vf = doc["ota_min_allowed_version_code"];
    if (vf.is<uint64_t>()) {
      ota_floor_value = vf.as<uint64_t>();
    } else if (vf.is<unsigned long>()) {
      ota_floor_value = static_cast<uint64_t>(vf.as<unsigned long>());
    } else if (vf.is<const char*>()) {
      const char* s = vf.as<const char*>();
      char* end = nullptr;
      unsigned long long parsed = strtoull(s ? s : "", &end, 10);
      if (!end || *end != '\0') {
        r.code = 400;
        r.body = "{\"ok\":false,\"error\":\"ERR_CONFIG_SCHEMA\",\"detail\":\"invalid ota_min_allowed_version_code\"}";
        return r;
      }
      ota_floor_value = static_cast<uint64_t>(parsed);
    } else {
      r.code = 400;
      r.body = "{\"ok\":false,\"error\":\"ERR_CONFIG_SCHEMA\",\"detail\":\"invalid ota_min_allowed_version_code\"}";
      return r;
    }
    if (ota_floor_value == 0) {
      r.code = 400;
      r.body = "{\"ok\":false,\"error\":\"ERR_CONFIG_SCHEMA\",\"detail\":\"ota_min_allowed_version_code must be > 0\"}";
      return r;
    }
  }

  if (ota_floor_set && !ota_version_set) {
    r.code = 400;
    r.body = "{\"ok\":false,\"error\":\"ERR_CONFIG_SCHEMA\",\"detail\":\"ota_version_code required when ota_min_allowed_version_code is set\"}";
    return r;
  }
  if (ota_floor_set && ota_floor_clear) {
    r.code = 400;
    r.body = "{\"ok\":false,\"error\":\"ERR_CONFIG_SCHEMA\",\"detail\":\"cannot set and clear ota_min_allowed_version_code together\"}";
    return r;
  }
  if (ota_signer_pem.length() > 0 && ota_signer_clear) {
    r.code = 400;
    r.body = "{\"ok\":false,\"error\":\"ERR_CONFIG_SCHEMA\",\"detail\":\"cannot set and clear ota_signer_public_key_pem together\"}";
    return r;
  }

  bool any_change = ota_version_set || ota_floor_set || ota_floor_clear || ota_signer_clear || ota_signer_pem.length() > 0;
  if (!any_change) {
    r.code = 400;
    r.body = "{\"ok\":false,\"error\":\"ERR_CONFIG_SCHEMA\",\"detail\":\"no OTA fields provided\"}";
    return r;
  }

  Preferences op;
  if (!op.begin("aztcfg", false)) {
    r.code = 500;
    r.body = "{\"ok\":false,\"error\":\"ERR_CONFIG_STATE\",\"detail\":\"preferences open failed\"}";
    return r;
  }

  if (ota_signer_clear) {
    kv_remove_key(op, "ota_signer_pem");
    kv_remove_key(op, "ota_signer_fp");
    state.ota_signer_override_public_key_pem = "";
    state.ota_signer_override_fingerprint_hex = "";
  } else if (ota_signer_pem.length() > 0) {
    String ota_fp;
    std::vector<uint8_t> ota_pub_raw;
    if (!b64_decode_vec(ota_signer_pem, ota_pub_raw) || ota_pub_raw.size() != crypto_sign_ed25519_PUBLICKEYBYTES) {
      op.end();
      r.code = 400;
      r.body = "{\"ok\":false,\"error\":\"ERR_CONFIG_OTA_SIGNER\",\"detail\":\"invalid ota signer key (expected ed25519 public_key_b64)\"}";
      return r;
    }
    uint8_t h[32] = {0};
    if (!sha256_bytes(ota_pub_raw.data(), ota_pub_raw.size(), h)) {
      op.end();
      r.code = 400;
      r.body = "{\"ok\":false,\"error\":\"ERR_CONFIG_OTA_SIGNER\",\"detail\":\"invalid ota signer hash\"}";
      return r;
    }
    ota_fp = hex_lower(h, sizeof(h));
    kv_set_string(op, "ota_signer_pem", ota_signer_pem);
    kv_set_string(op, "ota_signer_fp", ota_fp);
    state.ota_signer_override_public_key_pem = ota_signer_pem;
    state.ota_signer_override_fingerprint_hex = ota_fp;
  }

  if (ota_version_set) {
    op.putULong64("ota_last_vc", ota_version_value);
    state.last_ota_version_code = ota_version_value;
    state.last_ota_version = String((unsigned long long)ota_version_value);
    kv_set_string(op, "ota_last_ver", state.last_ota_version);
  }

  if (ota_floor_clear) {
    kv_remove_key(op, "ota_min_vc");
    kv_remove_key(op, "ota_min_ver_code");
    state.ota_min_allowed_version_code = 0;
  } else if (ota_floor_set) {
    uint64_t next_floor = state.ota_min_allowed_version_code;
    if (ota_floor_value > next_floor) next_floor = ota_floor_value;
    op.putULong64("ota_min_vc", next_floor);
    state.ota_min_allowed_version_code = next_floor;
  }

  op.end();

  r.code = 200;
  r.body = "{\"ok\":true,\"last_ota_version_code\":" + String(static_cast<unsigned long long>(state.last_ota_version_code)) +
           ",\"ota_min_allowed_version_code\":" + String(static_cast<unsigned long long>(state.ota_min_allowed_version_code)) +
           ",\"ota_signer_override_set\":" + String(state.ota_signer_override_public_key_pem.length() > 0 ? "true" : "false") + "}";
  return r;
}

bool validate_ota_bundle_header_line(const String& header_line,
                                     String& out_signer_fp,
                                     String& out_meta_b64,
                                     String& out_meta_sig_b64,
                                     String& out_err) {
  out_signer_fp = "";
  out_meta_b64 = "";
  out_meta_sig_b64 = "";
  out_err = "";

  if (header_line.length() < 20 || header_line.length() > constants::runtime::ota::kHeaderMaxBytes) {
    out_err = "invalid bundle header line";
    return false;
  }

  JsonDocument hdr;
  if (deserializeJson(hdr, header_line)) {
    out_err = "header json parse failed";
    return false;
  }
  if (String((const char*)(hdr["kind"] | "")) != "azt-ota-bundle") {
    out_err = "invalid bundle kind";
    return false;
  }

  out_signer_fp = String((const char*)(hdr["signer_fingerprint_hex"] | ""));
  out_meta_b64 = String((const char*)(hdr["meta_b64"] | ""));
  out_meta_sig_b64 = String((const char*)(hdr["meta_signature_b64"] | ""));
  if (out_signer_fp.length() != 64 || out_meta_b64.length() == 0 || out_meta_sig_b64.length() == 0) {
    out_err = "missing signed header fields";
    return false;
  }

  return true;
}

bool parse_u64_meta_field(const JsonDocument& meta,
                          const char* key,
                          uint64_t& out_value,
                          String& out_err) {
  out_value = 0;
  out_err = "";
  if (meta[key].isNull()) {
    out_err = String("missing ") + key;
    return false;
  }
  JsonVariantConst v = meta[key];
  if (v.is<uint64_t>()) {
    out_value = v.as<uint64_t>();
    return true;
  }
  if (v.is<unsigned long>()) {
    out_value = static_cast<uint64_t>(v.as<unsigned long>());
    return true;
  }
  if (v.is<const char*>()) {
    const char* s = v.as<const char*>();
    if (!s || strlen(s) == 0) {
      out_err = String("invalid ") + key;
      return false;
    }
    char* end = nullptr;
    unsigned long long parsed = strtoull(s, &end, 10);
    if (!end || *end != '\0') {
      out_err = String("invalid ") + key;
      return false;
    }
    out_value = static_cast<uint64_t>(parsed);
    return true;
  }
  out_err = String("invalid ") + key;
  return false;
}

bool validate_ota_firmware_meta(const JsonDocument& meta,
                                int& out_fw_size,
                                String& out_fw_sha,
                                String& out_err) {
  out_fw_size = meta["firmware_size"] | 0;
  out_fw_sha = String((const char*)(meta["firmware_sha256"] | ""));
  out_err = "";

  if (out_fw_size <= 0 || out_fw_sha.length() != 64) {
    out_err = "invalid firmware metadata";
    return false;
  }
  return true;
}

bool validate_ota_bundle_payload_lengths(int content_len,
                                         int header_line_len,
                                         int fw_size,
                                         int& out_bytes_left,
                                         String& out_err) {
  out_err = "";
  out_bytes_left = 0;

  if (content_len <= 0) {
    out_err = "missing content length";
    return false;
  }
  if (header_line_len < 0 || fw_size <= 0) {
    out_err = "invalid length inputs";
    return false;
  }

  const int consumed = header_line_len + 1;  // newline after header JSON
  out_bytes_left = content_len - consumed;
  if (out_bytes_left < fw_size) {
    out_err = "bundle payload shorter than firmware_size";
    return false;
  }
  if (out_bytes_left > fw_size) {
    out_err = "bundle payload longer than firmware_size";
    return false;
  }
  return true;
}

bool should_drain_trailing_bundle_bytes(int bytes_left) {
  return bytes_left > 0;
}

int ota_next_drain_chunk_size(int bytes_left, int buf_size) {
  if (bytes_left <= 0 || buf_size <= 0) return 0;
  return bytes_left > buf_size ? buf_size : bytes_left;
}

void ota_kick_wdt() {
  // Feed task watchdog when available and yield so IDLE task can run.
  // (esp_task_wdt_reset is safe to call even if current task is not subscribed.)
  esp_task_wdt_reset();
  vTaskDelay(1);
}

bool ota_stream_read_failed(int n_read) {
  return n_read <= 0;
}

bool ota_update_write_mismatch(size_t wrote, int expected) {
  return static_cast<int>(wrote) != expected;
}

bool ota_begin_failed(bool begin_ok) {
  return !begin_ok;
}

bool ota_read_firmware_chunk(WiFiClient& client,
                             uint8_t* buf,
                             int to_read,
                             int& out_n_read,
                             String& out_err,
                             uint32_t chunk_timeout_ms = constants::runtime::ota::kReadChunkTimeoutMs) {
  out_n_read = 0;
  out_err = "";

  if (to_read <= 0) {
    out_err = "invalid read size";
    return false;
  }

  uint32_t last_progress_ms = millis();
  while (client.connected() && out_n_read < to_read) {
    int avail = client.available();
    if (avail > 0) {
      int want = to_read - out_n_read;
      if (avail < want) want = avail;
      int n = client.read(buf + out_n_read, static_cast<size_t>(want));
      if (n > 0) {
        out_n_read += n;
        last_progress_ms = millis();
        ota_kick_wdt();  // keep scheduler/watchdog serviced during sustained RX
        continue;
      }
    }

    if ((millis() - last_progress_ms) > chunk_timeout_ms) {
      out_err = "stream read timeout during firmware body";
      return false;
    }

    ota_kick_wdt();  // cooperative yield while waiting for next bytes
  }

  if (out_n_read <= 0) {
    out_err = "stream read failed during firmware body";
    return false;
  }
  return true;
}

bool ota_sha_mismatch(const String& got_sha, const String& expected_sha) {
  return got_sha != expected_sha;
}

static constexpr size_t kOtaChunkBytes = 256;

#ifndef AZT_OTA_BREADCRUMBS
#define AZT_OTA_BREADCRUMBS 0
#endif

static inline void ota_bc(const char* tag);

struct OtaEraseTaskCtx {
  const esp_partition_t* part = nullptr;
  size_t total_len = 0;
  size_t chunk_bytes = constants::runtime::ota::kFlashSectorBytes;
  volatile bool failed = false;
  volatile bool done = false;
  String err;
};

static void ota_erase_task(void* arg) {
  OtaEraseTaskCtx* ctx = reinterpret_cast<OtaEraseTaskCtx*>(arg);
  if (!ctx || !ctx->part || ctx->total_len == 0 || ctx->chunk_bytes == 0) {
    if (ctx) {
      ctx->failed = true;
      ctx->err = "erase task invalid init";
      ctx->done = true;
    }
    vTaskDelete(nullptr);
    return;
  }

  for (size_t off = 0; off < ctx->total_len; off += ctx->chunk_bytes) {
    const size_t remain = ctx->total_len - off;
    const size_t chunk = (remain > ctx->chunk_bytes) ? ctx->chunk_bytes : remain;
    if (off == 0) ota_bc("S4A_ERASE_CALL_0_BEGIN");
    if (esp_partition_erase_range(ctx->part, off, chunk) != ESP_OK) {
      ctx->failed = true;
      ctx->err = "failed to erase OTA slot";
      ctx->done = true;
      vTaskDelete(nullptr);
      return;
    }
    if (off == 0) ota_bc("S4B_ERASE_CALL_0_OK");
    vTaskDelay(1);
  }

  ctx->done = true;
  vTaskDelete(nullptr);
}

static inline void ota_bc(const char* tag) {
#if AZT_OTA_BREADCRUMBS
  Serial.printf("AZT_OTA_BC %s\n", tag);
#else
  (void)tag;
#endif
}

struct OtaWriteMsg {
  bool end = false;
  uint32_t offset = 0;
  uint16_t len = 0;
  uint8_t data[kOtaChunkBytes] = {0};
};

struct OtaWriterCtx {
  QueueHandle_t q = nullptr;
  esp_ota_handle_t handle = 0;
  volatile bool failed = false;
  volatile bool done = false;
  esp_err_t write_err = ESP_OK;
};

static void ota_stop_writer(OtaWriterCtx& ctx, QueueHandle_t q, TaskHandle_t writer_task) {
  if (!q) return;
  OtaWriteMsg end_msg;
  end_msg.end = true;
  for (int i = 0; i < 10 && !ctx.done; ++i) {
    xQueueSend(q, &end_msg, pdMS_TO_TICKS(constants::runtime::ota::kQueueStopSendWaitMs));
    ota_kick_wdt();
  }
  uint32_t wait_deadline = millis() + 3000;
  while (!ctx.done && static_cast<int32_t>(millis() - wait_deadline) < 0) {
    ota_kick_wdt();
  }

  // Defensive teardown: if the writer task did not exit in time,
  // force-delete it before queue destruction to prevent queue UAF panic.
  if (!ctx.done && writer_task != nullptr) {
    vTaskDelete(writer_task);
    ctx.done = true;
  }
}

static void ota_writer_task(void* arg) {
  OtaWriterCtx* ctx = reinterpret_cast<OtaWriterCtx*>(arg);
  if (!ctx || !ctx->q) {
    vTaskDelete(nullptr);
    return;
  }

  OtaWriteMsg msg;
  while (true) {
    if (xQueueReceive(ctx->q, &msg, pdMS_TO_TICKS(250)) != pdTRUE) {
      if (ctx->failed) break;
      ota_kick_wdt();
      continue;
    }
    if (msg.end) break;
    if (msg.len == 0) continue;

    esp_err_t wr_err = esp_ota_write_with_offset(ctx->handle, msg.data, static_cast<size_t>(msg.len), msg.offset);
    if (wr_err != ESP_OK) {
      ctx->failed = true;
      ctx->write_err = wr_err;
      break;
    }
    ota_kick_wdt();
  }

  ctx->done = true;
  vTaskDelete(nullptr);
}

bool poison_ota_slot_header(const esp_partition_t* part) {
  // SECURITY FAIL-CLOSED: poison the target OTA header *before* writing
  // attacker-controlled bytes. If power is cut mid-update, the slot remains
  // non-bootable instead of potentially booting unverified code.
  if (!part) return false;
  constexpr size_t kHeaderSectorSize = constants::runtime::ota::kFlashSectorBytes;
  uint8_t zeros[kHeaderSectorSize] = {0};
  if (esp_partition_erase_range(part, 0, kHeaderSectorSize) != ESP_OK) return false;
  return esp_partition_write(part, 0, zeros, kHeaderSectorSize) == ESP_OK;
}

void drain_request_body_best_effort(WiFiClient& client, int max_bytes, uint32_t max_ms = 60000) {
  if (max_bytes <= 0) return;
  const uint32_t start = millis();
  uint32_t last_rx_ms = millis();
  constexpr uint32_t kQuietMs = 800;

  uint8_t buf[512];
  int left = max_bytes;

  while ((millis() - start) < max_ms) {
    int avail = client.available();
    if (avail > 0) {
      int want = left > (int)sizeof(buf) ? (int)sizeof(buf) : left;
      if (want <= 0) want = (int)sizeof(buf);
      if (avail < want) want = avail;

      int n = client.read(buf, static_cast<size_t>(want));
      if (n > 0) {
        left -= n;
        last_rx_ms = millis();
        if (left <= 0) break;
        continue;
      }
    }

    // If sender has gone quiet and no bytes are pending, stop draining.
    if (client.available() == 0 && (millis() - last_rx_ms) > kQuietMs) {
      break;
    }

    if (!client.connected() && client.available() == 0) {
      break;
    }

    vTaskDelay(1);
  }
}

static bool handle_ota_upgrade_bundle_post(WiFiClient& client, int content_len, AppState& state, String& out_err) {
  out_err = "";
  ota_bc("S0_ENTER");

  String header_line = client.readStringUntil('\n');
  header_line.trim();

  String signer_fp;
  String meta_b64;
  String meta_sig_b64;
  if (!validate_ota_bundle_header_line(header_line, signer_fp, meta_b64, meta_sig_b64, out_err)) {
    return false;
  }
  ota_bc("S1_HDR_OK");

  String trusted_pem = state.ota_signer_override_public_key_pem.length() > 0
                         ? state.ota_signer_override_public_key_pem
                         : String(kOtaSignerPublicKeyPem);
  String trusted_fp;
  std::vector<uint8_t> trusted_pub;
  if (!b64_decode_vec(trusted_pem, trusted_pub) || trusted_pub.size() != crypto_sign_ed25519_PUBLICKEYBYTES) {
    out_err = "trusted ota signer key invalid";
    return false;
  }
  uint8_t trusted_h[32] = {0};
  if (!sha256_bytes(trusted_pub.data(), trusted_pub.size(), trusted_h)) {
    out_err = "trusted ota signer hash failed";
    return false;
  }
  trusted_fp = hex_lower(trusted_h, sizeof(trusted_h));
  if (trusted_fp != signer_fp) {
    out_err = "signer fingerprint not trusted";
    return false;
  }

  std::vector<uint8_t> meta_raw;
  if (!b64_decode_vec(meta_b64, meta_raw) || meta_raw.empty()) {
    out_err = "meta_b64 invalid";
    return false;
  }
  if (!verify_ed25519_signature_b64(trusted_pem, meta_raw, meta_sig_b64)) {
    out_err = "meta signature verify failed";
    return false;
  }
  ota_bc("S2_META_SIG_OK");

  JsonDocument meta;
  if (deserializeJson(meta, meta_raw.data(), meta_raw.size())) {
    out_err = "meta json parse failed";
    return false;
  }

  String ota_target = String((const char*)(meta["target"] | ""));
#if CONFIG_IDF_TARGET_ESP32S3
  const char* expected_target = "atom-echos3r";
#else
  const char* expected_target = "atom-echo";
#endif
  if (ota_target.length() == 0) {
    out_err = "missing target in bundle metadata";
    return false;
  }
  if (!ota_target.equalsIgnoreCase(expected_target)) {
    out_err = String("target mismatch: bundle=") + ota_target + " device=" + expected_target;
    return false;
  }

  String ota_version = String((const char*)(meta["version"] | ""));
  uint64_t ota_version_code = 0;
  String vc_err;
  if (!parse_u64_meta_field(meta, "version_code", ota_version_code, vc_err) || ota_version_code == 0) {
    out_err = vc_err.length() ? vc_err : "invalid version_code";
    return false;
  }
  bool has_rollback_floor_code = false;
  uint64_t ota_rollback_floor_code = 0;
  String rf_err;
  if (!meta["rollback_floor_code"].isNull()) {
    has_rollback_floor_code = true;
    if (!parse_u64_meta_field(meta, "rollback_floor_code", ota_rollback_floor_code, rf_err)) {
      out_err = rf_err;
      return false;
    }
  } else {
    out_err = "missing rollback_floor_code (required for OTA bundle acceptance; set --rollback-floor-code, e.g. 'same')";
    return false;
  }

  if (ota_version_code < state.ota_min_allowed_version_code) {
    out_err = "version_code below rollback floor";
    return false;
  }

  uint64_t current_version_code = state.last_ota_version_code;
  if (current_version_code == 0 && state.last_ota_version.length() > 0) {
    char* end = nullptr;
    unsigned long long parsed = strtoull(state.last_ota_version.c_str(), &end, 10);
    if (end && *end == '\0') {
      current_version_code = static_cast<uint64_t>(parsed);
    }
  }
  if (current_version_code > 0 && ota_version_code == current_version_code) {
    out_err = "version_code equals current version";
    return false;
  }

  int fw_size = 0;
  String fw_sha;
  if (!validate_ota_firmware_meta(meta, fw_size, fw_sha, out_err)) {
    return false;
  }
  ota_bc("S3_META_FIELDS_OK");

  ota_bc("S3A_PREPARE_PARTITION");
  const esp_partition_t* target_part = esp_ota_get_next_update_partition(nullptr);
  if (!target_part) {
    out_err = "no OTA partition available";
    return false;
  }
  ota_bc("S3B_PARTITION_OK");
  if (static_cast<size_t>(fw_size) > target_part->size) {
    out_err = "firmware too large for OTA slot";
    return false;
  }

  int bytes_left = 0;
  if (!validate_ota_bundle_payload_lengths(content_len,
                                           static_cast<int>(header_line.length()),
                                           fw_size,
                                           bytes_left,
                                           out_err)) {
    return false;
  }
  ota_bc("S3C_LENGTHS_OK");

  constexpr size_t kFlashSector = constants::runtime::ota::kFlashSectorBytes;
  constexpr size_t kEraseChunkBytes = kFlashSector;
  const size_t erase_len = ((static_cast<size_t>(fw_size) + kFlashSector - 1) / kFlashSector) * kFlashSector;
  ota_bc("S3D_PRE_ERASE_LOOP");
  ota_bc("S4_ERASE_BEGIN");
  OtaEraseTaskCtx erase_ctx;
  erase_ctx.part = target_part;
  erase_ctx.total_len = erase_len;
  erase_ctx.chunk_bytes = kEraseChunkBytes;
  TaskHandle_t erase_task = nullptr;
  BaseType_t erase_ok = xTaskCreatePinnedToCore(ota_erase_task,
                                                 "azt_ota_erase",
                                                 constants::runtime::ota::kTaskStackErase,
                                                 &erase_ctx,
                                                 1,
                                                 &erase_task,
                                                 0);
  if (erase_ok != pdPASS || erase_task == nullptr) {
    out_err = "failed to start OTA erase task";
    return false;
  }
  uint32_t erase_wait_deadline = millis() + constants::runtime::ota::kEraseWaitMs;
  while (!erase_ctx.done && static_cast<int32_t>(millis() - erase_wait_deadline) < 0) {
    ota_kick_wdt();
  }
  if (!erase_ctx.done) {
    vTaskDelete(erase_task);
    out_err = "ota erase task timeout";
    return false;
  }
  if (erase_ctx.failed) {
    out_err = erase_ctx.err.length() ? erase_ctx.err : "failed to erase OTA slot";
    return false;
  }
  if (!poison_ota_slot_header(target_part)) {
    out_err = "failed to poison OTA slot header";
    return false;
  }
  ota_bc("S5_ERASE_POISON_OK");

  esp_ota_handle_t ota_handle = 0;
  ota_kick_wdt();
  esp_err_t begin_err = esp_ota_begin(target_part, OTA_SIZE_UNKNOWN, &ota_handle);
  ota_kick_wdt();
  if (begin_err != ESP_OK) {
    out_err = String("ota begin failed: ") + String(static_cast<int>(begin_err));
    return false;
  }
  ota_bc("S6_BEGIN_OK");

  const size_t first_block_len = std::min<size_t>(static_cast<size_t>(fw_size), kFlashSector);
  std::vector<uint8_t> first_block(first_block_len);

  mbedtls_sha256_context sha;
  mbedtls_sha256_init(&sha);
  mbedtls_sha256_starts_ret(&sha, 0);

  uint8_t buf[kOtaChunkBytes];

  // Two-stage OTA path: network reader feeds bounded queue, dedicated writer task drains to flash.
  // Security invariant preserved: first OTA header block is NOT written until SHA-256 verification succeeds.
  QueueHandle_t ota_q = xQueueCreate(constants::runtime::ota::kWriterQueueDepth, sizeof(OtaWriteMsg));
  if (!ota_q) {
    ota_bc("E_Q_CREATE_FAIL");
    mbedtls_sha256_free(&sha);
    esp_ota_abort(ota_handle);
    out_err = "failed to allocate OTA queue";
    return false;
  }

  OtaWriterCtx writer_ctx;
  writer_ctx.q = ota_q;
  writer_ctx.handle = ota_handle;

  TaskHandle_t writer_task = nullptr;
  BaseType_t writer_ok = xTaskCreatePinnedToCore(ota_writer_task,
                                                  "azt_ota_writer",
                                                  constants::runtime::ota::kTaskStackWriter,
                                                  &writer_ctx,
                                                  1,
                                                  &writer_task,
                                                  0);
  if (writer_ok != pdPASS || writer_task == nullptr) {
    vQueueDelete(ota_q);
    mbedtls_sha256_free(&sha);
    esp_ota_abort(ota_handle);
    out_err = "failed to start OTA writer task";
    return false;
  }
  ota_bc("S7_WRITER_START_OK");

  int remain_fw = fw_size;
  size_t fw_offset = 0;
  uint32_t q_highwater = 0;
  uint32_t q_backpressure_loops = 0;
  while (remain_fw > 0) {
    if (writer_ctx.failed) {
      mbedtls_sha256_free(&sha);
      esp_ota_abort(ota_handle);
      out_err = String("ota write failed: ") + String(static_cast<int>(writer_ctx.write_err));
      ota_stop_writer(writer_ctx, ota_q, writer_task);
      vQueueDelete(ota_q);
      return false;
    }

    int to_read = remain_fw > (int)sizeof(buf) ? (int)sizeof(buf) : remain_fw;
    int n = 0;
    String read_err;
    if (!ota_read_firmware_chunk(client, buf, to_read, n, read_err, constants::runtime::ota::kReadChunkTimeoutMs) || ota_stream_read_failed(n)) {
      mbedtls_sha256_free(&sha);
      writer_ctx.failed = true;
      esp_ota_abort(ota_handle);
      out_err = read_err.length() ? read_err : "stream read failed during firmware body";
      ota_stop_writer(writer_ctx, ota_q, writer_task);
      vQueueDelete(ota_q);
      return false;
    }

    mbedtls_sha256_update_ret(&sha, buf, static_cast<size_t>(n));

    size_t consumed = 0;
    if (fw_offset < first_block_len) {
      size_t copy_len = std::min<size_t>(static_cast<size_t>(n), first_block_len - fw_offset);
      memcpy(first_block.data() + fw_offset, buf, copy_len);
      consumed += copy_len;
      fw_offset += copy_len;
    }

    if (consumed < static_cast<size_t>(n)) {
      OtaWriteMsg msg;
      msg.end = false;
      msg.offset = static_cast<uint32_t>(fw_offset);
      msg.len = static_cast<uint16_t>(static_cast<size_t>(n) - consumed);
      memcpy(msg.data, buf + consumed, msg.len);

      while (xQueueSend(ota_q, &msg, pdMS_TO_TICKS(constants::runtime::ota::kQueuePushWaitMs)) != pdTRUE) {
        if (writer_ctx.failed) break;
        q_backpressure_loops++;
        ota_kick_wdt();  // bounded backpressure while queue is full
      }
      if (writer_ctx.failed) {
        mbedtls_sha256_free(&sha);
        esp_ota_abort(ota_handle);
        out_err = String("ota write failed: ") + String(static_cast<int>(writer_ctx.write_err));
        ota_stop_writer(writer_ctx, ota_q, writer_task);
        vQueueDelete(ota_q);
        return false;
      }
      fw_offset += msg.len;
    }

    remain_fw -= n;
    bytes_left -= n;
    UBaseType_t q_now = uxQueueMessagesWaiting(ota_q);
    if (q_now > q_highwater) q_highwater = static_cast<uint32_t>(q_now);
    ota_kick_wdt();
  }

  // Signal writer completion and wait for drain.
  OtaWriteMsg end_msg;
  end_msg.end = true;
  while (xQueueSend(ota_q, &end_msg, pdMS_TO_TICKS(constants::runtime::ota::kQueuePushWaitMs)) != pdTRUE) {
    if (writer_ctx.failed) break;
    ota_kick_wdt();
  }
  uint32_t writer_wait_deadline = millis() + 30000;
  while (!writer_ctx.done && static_cast<int32_t>(millis() - writer_wait_deadline) < 0) {
    ota_kick_wdt();
  }
  if (!writer_ctx.done) {
    writer_ctx.failed = true;
    mbedtls_sha256_free(&sha);
    esp_ota_abort(ota_handle);
    out_err = "ota writer did not drain in time";
    ota_stop_writer(writer_ctx, ota_q, writer_task);
    vQueueDelete(ota_q);
    return false;
  }
  if (writer_ctx.failed) {
    mbedtls_sha256_free(&sha);
    esp_ota_abort(ota_handle);
    out_err = String("ota write failed: ") + String(static_cast<int>(writer_ctx.write_err));
    ota_stop_writer(writer_ctx, ota_q, writer_task);
    vQueueDelete(ota_q);
    return false;
  }

  vQueueDelete(ota_q);
  ota_bc("S8_STREAM_DRAIN_OK");

  uint8_t digest[32] = {0};
  mbedtls_sha256_finish_ret(&sha, digest);
  mbedtls_sha256_free(&sha);
  String got_sha = hex_lower(digest, sizeof(digest));
  if (ota_sha_mismatch(got_sha, fw_sha)) {
    ota_bc("E_SHA_MISMATCH");
    esp_ota_abort(ota_handle);
    out_err = "firmware sha256 mismatch";
    return false;
  }
  ota_bc("S9_SHA_OK");

  if (!first_block.empty()) {
    ota_kick_wdt();
    esp_err_t hdr_wr_err = esp_ota_write_with_offset(ota_handle, first_block.data(), first_block.size(), 0);
    ota_kick_wdt();
    if (hdr_wr_err != ESP_OK) {
      esp_ota_abort(ota_handle);
      out_err = String("failed to restore OTA header block: ") + String(static_cast<int>(hdr_wr_err));
      return false;
    }
  }
  ota_bc("S10_HEADER_RESTORE_OK");

  ota_kick_wdt();
  esp_err_t end_err = esp_ota_end(ota_handle);
  ota_kick_wdt();
  if (end_err != ESP_OK) {
    out_err = String("ota end failed: ") + String(static_cast<int>(end_err));
    return false;
  }
  ota_bc("S11_END_OK");

  ota_kick_wdt();
  esp_err_t set_err = esp_ota_set_boot_partition(target_part);
  ota_kick_wdt();
  if (set_err != ESP_OK) {
    out_err = String("failed to set boot partition: ") + String(static_cast<int>(set_err));
    return false;
  }
  ota_bc("S12_SET_BOOT_OK");

  // Drain any trailing bytes in the bundle body (if present).
  while (should_drain_trailing_bundle_bytes(bytes_left) && client.connected()) {
    int want = ota_next_drain_chunk_size(bytes_left, static_cast<int>(sizeof(buf)));
    int n = client.readBytes(reinterpret_cast<char*>(buf), want);
    if (n <= 0) break;
    bytes_left -= n;
    ota_kick_wdt();
  }

  // Commit OTA version metadata only after full validation + successful Update.end().
  state.last_ota_version = ota_version;
  state.last_ota_version_code = ota_version_code;
  uint64_t next_floor = state.ota_min_allowed_version_code;
  if (has_rollback_floor_code && ota_rollback_floor_code > next_floor) next_floor = ota_rollback_floor_code;
  state.ota_min_allowed_version_code = next_floor;

  Preferences p;
  if (p.begin("aztcfg", false)) {
    kv_set_string(p, "ota_last_ver", state.last_ota_version);
    p.putULong64("ota_last_vc", state.last_ota_version_code);
    p.putULong64("ota_min_vc", state.ota_min_allowed_version_code);
    p.end();
  }

#if AZT_OTA_BREADCRUMBS
  Serial.printf("AZT_OTA_PIPELINE_OK q_highwater=%lu q_backpressure_loops=%lu fw_size=%d\n",
                static_cast<unsigned long>(q_highwater),
                static_cast<unsigned long>(q_backpressure_loops),
                fw_size);
#else
  (void)q_highwater;
  (void)q_backpressure_loops;
#endif

  return true;
}

static bool parse_request_and_headers(WiFiClient& client,
                                      String& method,
                                      String& path,
                                      int& content_len) {
  method = "";
  path = "";
  content_len = 0;

  client.setTimeout(4000);
  String req = client.readStringUntil('\n');
  req.trim();

  if (!parse_request_line(req, method, path)) {
    client.print("HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n");
    return false;
  }

  while (client.available() || client.connected()) {
    String h = client.readStringUntil('\n');
    if (h == "\r" || h.length() == 0) break;
    String hs = h;
    hs.trim();
    if (hs.startsWith("Content-Length:")) {
      String v = hs.substring(String("Content-Length:").length());
      v.trim();
      content_len = v.toInt();
    }
  }

  return true;
}

void handle_client_stream_only(WiFiClient& client, const AppState& state) {
  String method, path;
  int content_len = 0;
  if (!parse_request_and_headers(client, method, path, content_len)) return;

  String remote_ip = client.remoteIP().toString();
  if (!is_remote_ip_authorized(state, remote_ip)) {
    send_json(client, 403,
              "{\"ok\":false,\"error\":\"ERR_AUTH_LISTENER_IP\",\"detail\":\"listener IP not authorized\"}");
    return;
  }

  if (!(method == "GET" && path.startsWith("/stream"))) {
    send_json(client, 404,
              "{\"ok\":false,\"error\":\"ERR_STREAM_PORT_ROUTE\",\"detail\":\"this port serves /stream only\"}");
    return;
  }

  String stream_nonce;
  String stream_err;
  String stream_detail;
  if (!verify_stream_nonce_and_auth(path, state, stream_nonce, stream_err, stream_detail)) {
    String body = "{\"ok\":false,\"error\":" + json_quote(stream_err);
    if (stream_detail.length() > 0) body += ",\"detail\":" + json_quote(stream_detail);
    body += "}";
    send_json(client, 401, body);
    return;
  }

  handle_stream(client,
                parse_seconds_from_path(path),
                state,
                stream_nonce,
                parse_signbench_from_path(path),
                path.indexOf("telemetry=1") >= 0 || path.indexOf("telemetry=true") >= 0 || path.indexOf("telemetry=yes") >= 0 || path.indexOf("telemetry=on") >= 0,
                parse_drop_test_frames_from_path(path));
}

void handle_client_api_only(WiFiClient& client, AppState& state) {
  String method, path;
  int content_len = 0;
  if (!parse_request_and_headers(client, method, path, content_len)) return;

  String remote_ip = client.remoteIP().toString();
  if (!is_remote_ip_authorized(state, remote_ip)) {
    send_json(client, 403,
              "{\"ok\":false,\"error\":\"ERR_AUTH_LISTENER_IP\",\"detail\":\"listener IP not authorized\"}");
    return;
  }

  if (!state.managed) {
    send_json(client, 403,
              "{\"ok\":false,\"error\":\"ERR_BOOTSTRAP_SERIAL_REQUIRED\",\"detail\":\"network API disabled until admin key is pinned via serial\"}");
    return;
  }

  // Plain HTTP allowlist is intentionally tiny: hardened OTA wake/upgrade only.
  // All general API routes (config, reboot, certs, challenges, state, etc.) must use HTTPS.
  if (method == "POST" && path == "/api/v0/device/ota/wake") {
    send_json(client, 403,
              "{\"ok\":false,\"error\":\"ERR_HTTP_API_DISABLED\",\"detail\":\"use HTTPS API for this endpoint\"}");
    return;
  }

  if (method == "GET" && path == "/api/v0/device/upgrade") {
    uint32_t now_ms = millis();
    if (!ota_wake_window_allows_ip(remote_ip, now_ms)) {
      send_json(client, 403,
                "{\"ok\":false,\"error\":\"ERR_OTA_WAKE_REQUIRED\",\"detail\":\"OTA endpoint is closed; use /api/v0/device/ota/wake/challenge + signed POST /api/v0/device/ota/wake\"}");
      return;
    }

    String html = "<!doctype html><html><head><meta charset=\"utf-8\"><title>AZT OTA Upgrade</title></head><body>"
                  "<h1>AZT OTA Upgrade</h1>"
                  "<p>POST multipart firmware bundle to <code>/api/v0/device/upgrade</code>.</p>"
                  "</body></html>";
    client.print("HTTP/1.1 200 OK\r\n");
    client.print("Content-Type: text/html; charset=utf-8\r\n");
    client.print("Cache-Control: no-store\r\n");
    client.print("Connection: close\r\n");
    client.print("Content-Length: ");
    client.print(html.length());
    client.print("\r\n\r\n");
    client.print(html);
    return;
  }

  if (method == "POST" && path == "/api/v0/device/upgrade") {
    uint32_t now_ms = millis();
    if (!ota_wake_window_allows_ip(remote_ip, now_ms)) {
      send_json(client, 403,
                "{\"ok\":false,\"error\":\"ERR_OTA_WAKE_REQUIRED\",\"detail\":\"OTA endpoint is closed; use /api/v0/device/ota/wake/challenge + signed POST /api/v0/device/ota/wake\"}");
      return;
    }

    Serial.printf("AZT_OTA_POST begin content_len=%d from=%s\n", content_len, remote_ip.c_str());
    String err;
    if (handle_ota_upgrade_bundle_post(client, content_len, state, err)) {
      Serial.printf("AZT_OTA_POST ok\n");
      clear_ota_wake_window();
      send_json(client, 200, "{\"ok\":true,\"upgrade_written\":true,\"reboot_required\":true,\"detail\":\"firmware accepted; reboot to run new image\"}");
    } else {
      Serial.printf("AZT_OTA_POST err=%s\n", err.c_str());
      // Best-effort drain reduces TCP RSTs when rejecting while client is still uploading.
      drain_request_body_best_effort(client, content_len, 60000);
      send_json(client, 400, "{\"ok\":false,\"error\":\"ERR_OTA_UPGRADE\",\"detail\":" + json_quote(err) + "}");
    }
    return;
  }

  // Any other HTTP route is explicitly blocked; use HTTPS API instead.
  send_json(client, 403,
            "{\"ok\":false,\"error\":\"ERR_HTTP_API_DISABLED\",\"detail\":\"use HTTPS API for this endpoint\"}");
}

void handle_client(WiFiClient& client, AppState& state) {
  handle_client_api_only(client, state);
}

}  // namespace azt
