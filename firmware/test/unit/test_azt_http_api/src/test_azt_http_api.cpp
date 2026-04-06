#include "test_azt_registry.h"

#include <ArduinoJson.h>
#include <WiFi.h>

#include "azt_crypto.h"
#include "azt_http_api.h"
#include "azt_serial_control.h"
#include "azt_device_io.h"

namespace azt_test {
namespace {

static const char* kTestAdminEd25519PublicKeyB64 = "kZRQL/xXbZcnk8tjfOn/IHfOnCqCYmVWA5jD7JJFb1I=";

bool compute_test_admin_ed25519_fp(String& out_fp) {
  out_fp = "";
  std::vector<uint8_t> pub_raw;
  if (!azt::b64_decode_vec(String(kTestAdminEd25519PublicKeyB64), pub_raw)) return false;
  if (pub_raw.size() != 32) return false;
  uint8_t h[32] = {0};
  if (!azt::sha256_bytes(pub_raw.data(), pub_raw.size(), h)) return false;
  out_fp = azt::hex_lower(h, sizeof(h));
  return out_fp.length() == 64;
}

bool test_parse_request_line(Context&) {
  String m, p;
  if (!azt::parse_request_line("GET /api/v0/config/state HTTP/1.1", m, p)) return false;
  if (m != "GET" || p != "/api/v0/config/state") return false;
  if (azt::parse_request_line("BROKEN", m, p)) return false;
  return true;
}

bool test_parse_request_line_multiple_spaces(Context&) {
  String m, p;
  return azt::parse_request_line("POST   /api/v0/config   HTTP/1.1", m, p) &&
         m == "POST" && p == "/api/v0/config";
}

bool test_parse_request_line_missing_path(Context&) {
  String m, p;
  return !azt::parse_request_line("GET  HTTP/1.1", m, p);
}

bool test_parse_request_line_empty_method(Context&) {
  String m, p;
  return !azt::parse_request_line(" /api/v0/config HTTP/1.1", m, p);
}

bool test_parse_request_line_path_only(Context&) {
  String m, p;
  return !azt::parse_request_line("/api/v0/config", m, p);
}

bool test_parse_request_line_requires_http_version(Context&) {
  String m, p;
  return !azt::parse_request_line("GET /api/v0/config", m, p);
}

bool test_parse_request_line_accepts_tabs_and_trim(Context&) {
  String m, p;
  return azt::parse_request_line("\tGET\t/api/v0/config/state\tHTTP/1.1\t", m, p) &&
         m == "GET" && p == "/api/v0/config/state";
}

bool test_parse_request_line_rejects_non_slash_path(Context&) {
  String m, p;
  return !azt::parse_request_line("GET api/v1/config HTTP/1.1", m, p);
}

bool test_parse_request_line_rejects_extra_token(Context&) {
  String m, p;
  return !azt::parse_request_line("GET /api/v0/config HTTP/1.1 EXTRA", m, p);
}

bool test_upgrade_get_route_returns_upload_ui(Context&) {
  azt::AppState st{};
  auto r = azt::dispatch_request("GET", "/api/v0/device/upgrade", "", st);
  return r.code == 200 && r.content_type.indexOf("text/html") >= 0 &&
         r.body.indexOf("AZT OTA Upgrade") >= 0 &&
         r.body.indexOf("/api/v0/device/upgrade") >= 0;
}

bool test_ota_bundle_header_validation_invalid_kind(Context&) {
  String signer_fp, meta_b64, meta_sig_b64, err;
  String line = "{\"kind\":\"not-bundle\",\"signer_fingerprint_hex\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"meta_b64\":\"AAAA\",\"meta_signature_b64\":\"AAAA\"}";
  bool ok = azt::validate_ota_bundle_header_line(line, signer_fp, meta_b64, meta_sig_b64, err);
  return !ok && err == "invalid bundle kind";
}

bool test_ota_bundle_header_validation_missing_fields(Context&) {
  String signer_fp, meta_b64, meta_sig_b64, err;
  String line = "{\"kind\":\"azt-ota-bundle\",\"signer_fingerprint_hex\":\"abcd\",\"meta_b64\":\"\",\"meta_signature_b64\":\"\"}";
  bool ok = azt::validate_ota_bundle_header_line(line, signer_fp, meta_b64, meta_sig_b64, err);
  return !ok && err == "missing signed header fields";
}

bool test_ota_bundle_header_validation_success(Context&) {
  String signer_fp, meta_b64, meta_sig_b64, err;
  String fp = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
  String line = "{\"kind\":\"azt-ota-bundle\",\"signer_fingerprint_hex\":\"" + fp + "\",\"meta_b64\":\"QUJD\",\"meta_signature_b64\":\"REVG\"}";
  bool ok = azt::validate_ota_bundle_header_line(line, signer_fp, meta_b64, meta_sig_b64, err);
  return ok && err.length() == 0 && signer_fp == fp && meta_b64 == "QUJD" && meta_sig_b64 == "REVG";
}

bool test_ota_firmware_meta_validation(Context&) {
  int fw_size = 0;
  String fw_sha, err;

  JsonDocument bad;
  bad["firmware_size"] = 0;
  bad["firmware_sha256"] = "abcd";
  if (azt::validate_ota_firmware_meta(bad, fw_size, fw_sha, err)) return false;
  if (err != "invalid firmware metadata") return false;

  JsonDocument good;
  good["firmware_size"] = 1234;
  good["firmware_sha256"] = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
  if (!azt::validate_ota_firmware_meta(good, fw_size, fw_sha, err)) return false;
  return fw_size == 1234 && fw_sha.length() == 64;
}

bool test_ota_bundle_payload_lengths_validation(Context&) {
  int bytes_left = 0;
  String err;

  if (azt::validate_ota_bundle_payload_lengths(0, 100, 10, bytes_left, err)) return false;
  if (err != "missing content length") return false;

  if (azt::validate_ota_bundle_payload_lengths(100, -1, 10, bytes_left, err)) return false;
  if (err != "invalid length inputs") return false;

  if (azt::validate_ota_bundle_payload_lengths(100, 20, 90, bytes_left, err)) return false;
  if (err != "bundle payload shorter than firmware_size") return false;

  if (!azt::validate_ota_bundle_payload_lengths(111, 20, 90, bytes_left, err)) return false;
  return err.length() == 0 && bytes_left == 90;
}

bool test_ota_trailing_drain_helpers(Context&) {
  if (azt::should_drain_trailing_bundle_bytes(0)) return false;
  if (!azt::should_drain_trailing_bundle_bytes(1)) return false;

  if (azt::ota_next_drain_chunk_size(0, 64) != 0) return false;
  if (azt::ota_next_drain_chunk_size(10, 0) != 0) return false;
  if (azt::ota_next_drain_chunk_size(10, 64) != 10) return false;
  return azt::ota_next_drain_chunk_size(100, 64) == 64;
}

bool test_ota_transport_error_helpers(Context&) {
  if (!azt::ota_stream_read_failed(0)) return false;
  if (!azt::ota_stream_read_failed(-1)) return false;
  if (azt::ota_stream_read_failed(1)) return false;

  if (azt::ota_update_write_mismatch(static_cast<size_t>(8), 8)) return false;
  if (!azt::ota_update_write_mismatch(static_cast<size_t>(7), 8)) return false;
  return !azt::ota_update_write_mismatch(static_cast<size_t>(0), 0);
}

bool test_ota_update_flow_error_helpers(Context&) {
  if (!azt::ota_begin_failed(false)) return false;
  if (azt::ota_begin_failed(true)) return false;

  if (!azt::ota_sha_mismatch("aa", "bb")) return false;
  if (azt::ota_sha_mismatch("cc", "cc")) return false;

  if (!azt::ota_end_failed(false)) return false;
  if (azt::ota_end_failed(true)) return false;

  if (!azt::ota_should_abort_on_error(true)) return false;
  return !azt::ota_should_abort_on_error(false);
}

bool test_dispatch_request_basic_routes(Context&) {
  azt::AppState st;
  st.managed = false;
  st.signed_config_ready = false;
  st.admin_fingerprint_hex = "abc";
  st.listener_fingerprint_hex = "def";
  st.device_sign_public_key_b64 = "PUB";
  st.device_sign_fingerprint_hex = "FP";

  auto r1 = azt::dispatch_request("GET", "/stream?seconds=9", "", st);
  if (!r1.wants_stream || r1.stream_seconds != 9 || r1.stream_signbench_each_chunk) return false;

  auto r1b = azt::dispatch_request("GET", "/stream?seconds=9&sigbench=1", "", st);
  if (!r1b.wants_stream || !r1b.stream_signbench_each_chunk) return false;

  auto r1c = azt::dispatch_request("GET", "/stream?seconds=9&telemetry=1&drop_test_frames=5", "", st);
  if (!r1c.wants_stream || !r1c.stream_enable_telemetry || r1c.stream_drop_test_frames != 5) return false;

  auto r2 = azt::dispatch_request("GET", "/api/v0/config/state", "", st);
  if (r2.wants_stream || r2.code != 200) return false;
  if (r2.body.indexOf("UNSET_ADMIN") < 0) return false;
  if (r2.body.indexOf("device_sign_alg") < 0) return false;
  if (r2.body.indexOf("device_sign_public_key_b64") < 0) return false;
  if (r2.body.indexOf("listener_key_configured") < 0) return false;

  auto r3 = azt::dispatch_request("GET", "/nope", "", st);
  if (r3.wants_stream || r3.code != 404) return false;
  return r3.content_type == "text/plain";
}

bool test_parse_wifi_values(Context&) {
  JsonDocument doc_ok;
  deserializeJson(doc_ok, "{\"wifi\":{\"ssid\":\"A\",\"password\":\"B\"}}");
  String ssid, pass;
  if (!azt::parse_wifi_values(doc_ok, ssid, pass)) return false;
  if (ssid != "A" || pass != "B") return false;

  JsonDocument doc_bad1;
  deserializeJson(doc_bad1, "{}");
  if (azt::parse_wifi_values(doc_bad1, ssid, pass)) return false;

  JsonDocument doc_bad2;
  deserializeJson(doc_bad2, "{\"wifi\":{\"ssid\":\"\",\"password\":\"x\"}}");
  if (azt::parse_wifi_values(doc_bad2, ssid, pass)) return false;

  JsonDocument doc_bad3;
  deserializeJson(doc_bad3, "{\"wifi\":\"oops\"}");
  if (azt::parse_wifi_values(doc_bad3, ssid, pass)) return false;

  JsonDocument doc_spaces;
  deserializeJson(doc_spaces, "{\"wifi\":{\"ssid\":\"  A  \",\"password\":\"  B  \"}}");
  if (!azt::parse_wifi_values(doc_spaces, ssid, pass)) return false;
  if (ssid != "  A  " || pass != "  B  ") return false;

  return true;
}

bool test_parse_header_key_values(Context& ctx) {
  String fp;
  if (!compute_test_admin_ed25519_fp(fp)) return false;

  JsonDocument ok;
  ok["admin_key"]["alg"] = "ed25519";
  ok["admin_key"]["public_key_b64"] = kTestAdminEd25519PublicKeyB64;
  ok["admin_key"]["fingerprint_alg"] = "sha256-raw-ed25519-pub";
  ok["admin_key"]["fingerprint_hex"] = fp;

  String out_pem, out_fp;
  if (!azt::parse_header_key_values(ok, out_pem, out_fp)) return false;
  if (out_fp != fp) return false;

  JsonDocument bad_alg = ok;
  bad_alg["admin_key"]["alg"] = "bad";
  if (azt::parse_header_key_values(bad_alg, out_pem, out_fp)) return false;

  JsonDocument bad_fp = ok;
  bad_fp["admin_key"]["fingerprint_hex"] = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
  if (azt::parse_header_key_values(bad_fp, out_pem, out_fp)) return false;

  return true;
}

bool test_parse_header_key_values_missing_admin_key(Context&) {
  JsonDocument doc;
  String out_pem, out_fp;
  return !azt::parse_header_key_values(doc, out_pem, out_fp);
}

bool test_parse_header_key_values_wrong_fingerprint_alg(Context& ctx) {
  String fp;
  if (!compute_test_admin_ed25519_fp(fp)) return false;

  JsonDocument doc;
  doc["admin_key"]["alg"] = "ed25519";
  doc["admin_key"]["public_key_b64"] = kTestAdminEd25519PublicKeyB64;
  doc["admin_key"]["fingerprint_alg"] = "sha256";
  doc["admin_key"]["fingerprint_hex"] = fp;

  String out_pem, out_fp;
  return !azt::parse_header_key_values(doc, out_pem, out_fp);
}

bool test_parse_header_key_values_invalid_fingerprint_length(Context& ctx) {
  if (!ctx.pubkey_pem || ctx.pubkey_pem->length() < 64) return false;

  JsonDocument doc;
  doc["admin_key"]["alg"] = "ed25519";
  doc["admin_key"]["public_key_b64"] = kTestAdminEd25519PublicKeyB64;
  doc["admin_key"]["fingerprint_alg"] = "sha256-raw-ed25519-pub";
  doc["admin_key"]["fingerprint_hex"] = "abcd";

  String out_pem, out_fp;
  return !azt::parse_header_key_values(doc, out_pem, out_fp);
}

bool test_parse_header_key_values_invalid_public_pem(Context& ctx) {
  String fp;
  if (!compute_test_admin_ed25519_fp(fp)) return false;

  JsonDocument doc;
  doc["admin_key"]["alg"] = "ed25519";
  doc["admin_key"]["public_key_b64"] = "NOT_B64";
  doc["admin_key"]["fingerprint_alg"] = "sha256-raw-ed25519-pub";
  doc["admin_key"]["fingerprint_hex"] = fp;

  String out_pem, out_fp;
  return !azt::parse_header_key_values(doc, out_pem, out_fp);
}

bool test_config_post_requires_signature_unmanaged(Context& ctx) {
  String fp;
  if (!compute_test_admin_ed25519_fp(fp)) return false;

  azt::AppState st{};
  st.managed = false;
  st.signed_config_ready = false;

  JsonDocument doc;
  doc["config_version"] = 1;
  doc["device_label"] = "dev";
  doc["admin_key"]["alg"] = "ed25519";
  doc["admin_key"]["public_key_b64"] = kTestAdminEd25519PublicKeyB64;
  doc["admin_key"]["fingerprint_alg"] = "sha256-raw-ed25519-pub";
  doc["admin_key"]["fingerprint_hex"] = fp;
  doc["wifi"]["ssid"] = "s";
  doc["wifi"]["password"] = "p";
  doc["time"]["server"] = "pool.ntp.org";
  doc["audio"]["sample_rate_hz"] = 16000;
  doc["audio"]["channels"] = 1;
  doc["audio"]["sample_width_bytes"] = 2;

  String body;
  serializeJson(doc, body);

  auto r = azt::dispatch_request("POST", "/api/v0/config", body, st);
  return r.code == 401 && r.body.indexOf("ERR_CONFIG_SIGNATURE") >= 0;
}

bool test_config_post_rejects_ota_signer_override_via_api(Context& ctx) {
  String fp;
  if (!compute_test_admin_ed25519_fp(fp)) return false;

  azt::AppState st{};
  st.managed = false;
  st.signed_config_ready = false;

  JsonDocument doc;
  doc["config_version"] = 1;
  doc["device_label"] = "dev";
  doc["admin_key"]["alg"] = "ed25519";
  doc["admin_key"]["public_key_b64"] = kTestAdminEd25519PublicKeyB64;
  doc["admin_key"]["fingerprint_alg"] = "sha256-raw-ed25519-pub";
  doc["admin_key"]["fingerprint_hex"] = fp;
  doc["ota_signer_public_key_pem"] = kTestAdminEd25519PublicKeyB64;
  doc["wifi"]["ssid"] = "s";
  doc["wifi"]["password"] = "p";
  doc["time"]["server"] = "pool.ntp.org";
  doc["audio"]["sample_rate_hz"] = 16000;
  doc["audio"]["channels"] = 1;
  doc["audio"]["sample_width_bytes"] = 2;

  String body;
  serializeJson(doc, body);

  auto r = azt::dispatch_request("POST", "/api/v0/config", body, st);
  return (r.code == 403 && r.body.indexOf("ERR_CONFIG_OTA_SERIAL_ONLY") >= 0) || (r.code == 401 && r.body.indexOf("ERR_CONFIG_SIGNATURE") >= 0);
}

bool test_signing_public_key_endpoint_pem(Context&) {
  azt::AppState st{};
  st.device_sign_public_key_b64 = "X8mNhhWS6qi5fYzNfMP6GSGUj9Yqkh6KI5/kj9rtYWE=";

  auto r = azt::dispatch_request("GET", "/api/v0/device/signing-public-key.pem", "", st);
  return r.code == 200 && r.content_type == "application/x-pem-file" &&
         r.body.indexOf("BEGIN PUBLIC KEY") >= 0;
}

bool test_attestation_nonce_too_short(Context&) {
  azt::AppState st{};
  auto r = azt::dispatch_request("GET", "/api/v0/device/attestation?nonce=abc", "", st);
  return r.code == 400 && r.body.indexOf("ERR_ATTEST_NONCE") >= 0;
}

bool test_attestation_nonce_missing(Context&) {
  azt::AppState st{};
  auto r = azt::dispatch_request("GET", "/api/v0/device/attestation", "", st);
  return r.code == 400 && r.body.indexOf("ERR_ATTEST_NONCE") >= 0;
}

bool test_stream_query_telemetry_truthy_variants(Context&) {
  azt::AppState st{};
  auto r1 = azt::dispatch_request("GET", "/stream?telemetry=true", "", st);
  auto r2 = azt::dispatch_request("GET", "/stream?telemetry=yes", "", st);
  auto r3 = azt::dispatch_request("GET", "/stream?telemetry=on", "", st);
  auto r4 = azt::dispatch_request("GET", "/stream?telemetry=TRUE", "", st);
  return r1.wants_stream && r1.stream_enable_telemetry &&
         r2.wants_stream && r2.stream_enable_telemetry &&
         r3.wants_stream && r3.stream_enable_telemetry &&
         r4.wants_stream && !r4.stream_enable_telemetry;
}

bool test_stream_query_drop_test_frames_invalid_defaults_zero(Context&) {
  azt::AppState st{};
  auto r1 = azt::dispatch_request("GET", "/stream?drop_test_frames=abc", "", st);
  auto r2 = azt::dispatch_request("GET", "/stream?drop_test_frames=-1", "", st);
  return r1.wants_stream && r1.stream_drop_test_frames == 0 &&
         r2.wants_stream && r2.stream_drop_test_frames == 0;
}

bool test_reboot_endpoint_sets_flag(Context&) {
  // Reboot endpoint is authenticated via challenge/signature; unmanaged state should reject.
  azt::AppState st{};
  auto r = azt::dispatch_request("POST", "/api/v0/device/reboot", "", st);
  return r.code == 409 && r.content_type == "application/json" && !r.reboot_after_response &&
         r.body.indexOf("ERR_REBOOT_AUTH_NOT_READY") >= 0;
}

bool test_signing_public_key_endpoint_alias(Context&) {
  azt::AppState st{};
  st.device_sign_public_key_b64 = "X8mNhhWS6qi5fYzNfMP6GSGUj9Yqkh6KI5/kj9rtYWE=";
  auto r = azt::dispatch_request("GET", "/api/v0/device/signing-public-key", "", st);
  return r.code == 200 && r.body.indexOf("BEGIN PUBLIC KEY") >= 0;
}

bool test_config_post_rejects_invalid_listener_key(Context& ctx) {
  String fp;
  if (!compute_test_admin_ed25519_fp(fp)) return false;

  azt::AppState st{};
  st.managed = false;

  JsonDocument doc;
  doc["config_version"] = 1;
  doc["device_label"] = "dev";
  doc["admin_key"]["alg"] = "ed25519";
  doc["admin_key"]["public_key_b64"] = kTestAdminEd25519PublicKeyB64;
  doc["admin_key"]["fingerprint_alg"] = "sha256-raw-ed25519-pub";
  doc["admin_key"]["fingerprint_hex"] = fp;
  doc["listener_key"]["alg"] = "bad-alg";
  doc["listener_key"]["public_key_pem"] = *ctx.pubkey_pem;
  doc["listener_key"]["fingerprint_alg"] = "sha256-spki-der";
  { String recfp; azt::compute_pubkey_spki_sha256_hex(*ctx.pubkey_pem, recfp); doc["listener_key"]["fingerprint_hex"] = recfp; }
  doc["wifi"]["ssid"] = "s";
  doc["wifi"]["password"] = "p";
  doc["time"]["server"] = "pool.ntp.org";
  doc["audio"]["sample_rate_hz"] = 16000;
  doc["audio"]["channels"] = 1;
  doc["audio"]["sample_width_bytes"] = 2;

  String body;
  serializeJson(doc, body);
  auto r = azt::dispatch_request("POST", "/api/v0/config", body, st);
  return r.code == 400 || (r.code == 401 && r.body.indexOf("ERR_CONFIG_SIGNATURE") >= 0);
}

bool test_config_post_rejects_invalid_time(Context& ctx) {
  String fp;
  if (!compute_test_admin_ed25519_fp(fp)) return false;

  azt::AppState st{};
  st.managed = false;

  JsonDocument doc;
  doc["config_version"] = 1;
  doc["device_label"] = "dev";
  doc["admin_key"]["alg"] = "ed25519";
  doc["admin_key"]["public_key_b64"] = kTestAdminEd25519PublicKeyB64;
  doc["admin_key"]["fingerprint_alg"] = "sha256-raw-ed25519-pub";
  doc["admin_key"]["fingerprint_hex"] = fp;
  doc["wifi"]["ssid"] = "s";
  doc["wifi"]["password"] = "p";
  doc["time"]["servers"] = "bad-not-array";
  doc["audio"]["sample_rate_hz"] = 16000;
  doc["audio"]["channels"] = 1;
  doc["audio"]["sample_width_bytes"] = 2;

  String body;
  serializeJson(doc, body);
  auto r = azt::dispatch_request("POST", "/api/v0/config", body, st);
  return r.code == 400 || (r.code == 401 && r.body.indexOf("ERR_CONFIG_SIGNATURE") >= 0);
}

bool test_config_post_rejects_invalid_authorized_listener_ips_type(Context& ctx) {
  String fp;
  if (!compute_test_admin_ed25519_fp(fp)) return false;

  azt::AppState st{};
  st.managed = false;

  JsonDocument doc;
  doc["config_version"] = 1;
  doc["device_label"] = "dev";
  doc["admin_key"]["alg"] = "ed25519";
  doc["admin_key"]["public_key_b64"] = kTestAdminEd25519PublicKeyB64;
  doc["admin_key"]["fingerprint_alg"] = "sha256-raw-ed25519-pub";
  doc["admin_key"]["fingerprint_hex"] = fp;
  doc["authorized_listener_ips"] = "not-an-array";
  doc["wifi"]["ssid"] = "s";
  doc["wifi"]["password"] = "p";
  doc["time"]["server"] = "pool.ntp.org";
  doc["audio"]["sample_rate_hz"] = 16000;
  doc["audio"]["channels"] = 1;
  doc["audio"]["sample_width_bytes"] = 2;

  String body;
  serializeJson(doc, body);
  auto r = azt::dispatch_request("POST", "/api/v0/config", body, st);
  return r.code == 400 || (r.code == 401 && r.body.indexOf("ERR_CONFIG_SIGNATURE") >= 0);
}

bool test_config_post_rejects_invalid_authorized_listener_ip_value(Context& ctx) {
  String fp;
  if (!compute_test_admin_ed25519_fp(fp)) return false;

  azt::AppState st{};
  st.managed = false;

  JsonDocument doc;
  doc["config_version"] = 1;
  doc["device_label"] = "dev";
  doc["admin_key"]["alg"] = "ed25519";
  doc["admin_key"]["public_key_b64"] = kTestAdminEd25519PublicKeyB64;
  doc["admin_key"]["fingerprint_alg"] = "sha256-raw-ed25519-pub";
  doc["admin_key"]["fingerprint_hex"] = fp;
  JsonArray ips = doc["authorized_listener_ips"].to<JsonArray>();
  ips.add("300.1.1.1");
  doc["wifi"]["ssid"] = "s";
  doc["wifi"]["password"] = "p";
  doc["time"]["server"] = "pool.ntp.org";
  doc["audio"]["sample_rate_hz"] = 16000;
  doc["audio"]["channels"] = 1;
  doc["audio"]["sample_width_bytes"] = 2;

  String body;
  serializeJson(doc, body);
  auto r = azt::dispatch_request("POST", "/api/v0/config", body, st);
  return r.code == 400 || (r.code == 401 && r.body.indexOf("ERR_CONFIG_SIGNATURE") >= 0);
}

bool test_signing_public_key_endpoint_invalid_device_key(Context&) {
  azt::AppState st{};
  st.device_sign_public_key_b64 = "bad";
  auto r = azt::dispatch_request("GET", "/api/v0/device/signing-public-key.pem", "", st);
  return r.code == 500;
}

bool test_attestation_nonce_too_long(Context&) {
  azt::AppState st{};
  String long_nonce;
  long_nonce.reserve(300);
  for (int i = 0; i < 280; ++i) long_nonce += 'a';
  auto r = azt::dispatch_request("GET", "/api/v0/device/attestation?nonce=" + long_nonce, "", st);
  return r.code == 400 && r.body.indexOf("ERR_ATTEST_NONCE") >= 0;
}

bool test_config_post_invalid_json(Context&) {
  azt::AppState st{};
  st.managed = false;
  auto r = azt::dispatch_request("POST", "/api/v0/config", "{not-json", st);
  return r.code == 400 && r.body.indexOf("ERR_CONFIG_SCHEMA") >= 0 && r.body.indexOf("invalid json") >= 0;
}

bool test_signing_public_key_endpoint_missing_device_key(Context&) {
  azt::AppState st{};
  st.device_sign_public_key_b64 = "";
  auto r = azt::dispatch_request("GET", "/api/v0/device/signing-public-key.pem", "", st);
  return r.code == 500;
}

bool test_signing_public_key_alias_invalid_device_key(Context&) {
  azt::AppState st{};
  st.device_sign_public_key_b64 = "bad";
  auto r = azt::dispatch_request("GET", "/api/v0/device/signing-public-key", "", st);
  return r.code == 500;
}

bool test_signing_public_key_alias_missing_device_key(Context&) {
  azt::AppState st{};
  st.device_sign_public_key_b64 = "";
  auto r = azt::dispatch_request("GET", "/api/v0/device/signing-public-key", "", st);
  return r.code == 500;
}

bool test_attestation_valid_nonce_reaches_non_schema_path(Context&) {
  azt::AppState st{};
  auto r = azt::dispatch_request("GET", "/api/v0/device/attestation?nonce=12345678", "", st);
  return !(r.code == 400 && r.body.indexOf("ERR_ATTEST_NONCE") >= 0);
}

bool test_attestation_max_nonce_len_schema_accepts(Context&) {
  azt::AppState st{};
  String n;
  n.reserve(256);
  for (int i = 0; i < 256; ++i) n += 'a';
  auto r = azt::dispatch_request("GET", "/api/v0/device/attestation?nonce=" + n, "", st);
  return !(r.code == 400 && r.body.indexOf("ERR_ATTEST_NONCE") >= 0);
}

bool test_config_post_rejects_wrong_version(Context& ctx) {
  String fp;
  if (!compute_test_admin_ed25519_fp(fp)) return false;

  azt::AppState st{};
  st.managed = false;

  JsonDocument doc;
  doc["config_version"] = 2;
  doc["device_label"] = "dev";
  doc["admin_key"]["alg"] = "ed25519";
  doc["admin_key"]["public_key_b64"] = kTestAdminEd25519PublicKeyB64;
  doc["admin_key"]["fingerprint_alg"] = "sha256-raw-ed25519-pub";
  doc["admin_key"]["fingerprint_hex"] = fp;
  doc["wifi"]["ssid"] = "s";
  doc["wifi"]["password"] = "p";
  doc["time"]["server"] = "pool.ntp.org";

  String body;
  serializeJson(doc, body);
  auto r = azt::dispatch_request("POST", "/api/v0/config", body, st);
  return r.code == 400 || (r.code == 401 && r.body.indexOf("ERR_CONFIG_SIGNATURE") >= 0);
}

bool test_config_post_rejects_missing_device_label(Context& ctx) {
  String fp;
  if (!compute_test_admin_ed25519_fp(fp)) return false;

  azt::AppState st{};
  st.managed = false;

  JsonDocument doc;
  doc["config_version"] = 1;
  doc["admin_key"]["alg"] = "ed25519";
  doc["admin_key"]["public_key_b64"] = kTestAdminEd25519PublicKeyB64;
  doc["admin_key"]["fingerprint_alg"] = "sha256-raw-ed25519-pub";
  doc["admin_key"]["fingerprint_hex"] = fp;
  doc["wifi"]["ssid"] = "s";
  doc["wifi"]["password"] = "p";
  doc["time"]["server"] = "pool.ntp.org";

  String body;
  serializeJson(doc, body);
  auto r = azt::dispatch_request("POST", "/api/v0/config", body, st);
  return r.code == 400 || (r.code == 401 && r.body.indexOf("ERR_CONFIG_SIGNATURE") >= 0);
}

bool test_config_post_rejects_invalid_wifi_object(Context& ctx) {
  String fp;
  if (!compute_test_admin_ed25519_fp(fp)) return false;

  azt::AppState st{};
  st.managed = false;

  JsonDocument doc;
  doc["config_version"] = 1;
  doc["device_label"] = "dev";
  doc["admin_key"]["alg"] = "ed25519";
  doc["admin_key"]["public_key_b64"] = kTestAdminEd25519PublicKeyB64;
  doc["admin_key"]["fingerprint_alg"] = "sha256-raw-ed25519-pub";
  doc["admin_key"]["fingerprint_hex"] = fp;
  doc["wifi"]["ssid"] = "";
  doc["wifi"]["password"] = "p";
  doc["time"]["server"] = "pool.ntp.org";

  String body;
  serializeJson(doc, body);
  auto r = azt::dispatch_request("POST", "/api/v0/config", body, st);
  return r.code == 400 || (r.code == 401 && r.body.indexOf("ERR_CONFIG_SIGNATURE") >= 0);
}

bool test_config_post_rejects_invalid_admin_key(Context& ctx) {
  String fp;
  if (!compute_test_admin_ed25519_fp(fp)) return false;

  azt::AppState st{};
  st.managed = false;

  JsonDocument doc;
  doc["config_version"] = 1;
  doc["device_label"] = "dev";
  doc["admin_key"]["alg"] = "bad-alg";
  doc["admin_key"]["public_key_b64"] = kTestAdminEd25519PublicKeyB64;
  doc["admin_key"]["fingerprint_alg"] = "sha256-raw-ed25519-pub";
  doc["admin_key"]["fingerprint_hex"] = fp;
  doc["wifi"]["ssid"] = "s";
  doc["wifi"]["password"] = "p";
  doc["time"]["server"] = "pool.ntp.org";

  String body;
  serializeJson(doc, body);
  auto r = azt::dispatch_request("POST", "/api/v0/config", body, st);
  return r.code == 400 && r.body.indexOf("invalid admin_key object") >= 0;
}

bool test_config_post_requires_signature_managed(Context& ctx) {
  String fp;
  if (!compute_test_admin_ed25519_fp(fp)) return false;

  azt::AppState st{};
  st.managed = true;
  st.signed_config_ready = true;
  st.admin_pubkey_pem = kTestAdminEd25519PublicKeyB64;
  st.admin_fingerprint_hex = fp;

  JsonDocument doc;
  doc["config_version"] = 1;
  doc["device_label"] = "dev";
  doc["admin_key"]["alg"] = "ed25519";
  doc["admin_key"]["public_key_b64"] = kTestAdminEd25519PublicKeyB64;
  doc["admin_key"]["fingerprint_alg"] = "sha256-raw-ed25519-pub";
  doc["admin_key"]["fingerprint_hex"] = fp;
  doc["wifi"]["ssid"] = "s";
  doc["wifi"]["password"] = "p";
  doc["time"]["server"] = "pool.ntp.org";

  String body;
  serializeJson(doc, body);
  auto r = azt::dispatch_request("POST", "/api/v0/config", body, st);
  return r.code == 401 && r.body.indexOf("ERR_CONFIG_SIGNATURE") >= 0;
}

bool test_config_post_rejects_empty_time_server(Context& ctx) {
  String fp;
  if (!compute_test_admin_ed25519_fp(fp)) return false;

  azt::AppState st{};
  st.managed = false;

  JsonDocument doc;
  doc["config_version"] = 1;
  doc["device_label"] = "dev";
  doc["admin_key"]["alg"] = "ed25519";
  doc["admin_key"]["public_key_b64"] = kTestAdminEd25519PublicKeyB64;
  doc["admin_key"]["fingerprint_alg"] = "sha256-raw-ed25519-pub";
  doc["admin_key"]["fingerprint_hex"] = fp;
  doc["wifi"]["ssid"] = "s";
  doc["wifi"]["password"] = "p";
  doc["time"]["server"] = "   ";

  String body;
  serializeJson(doc, body);
  auto r = azt::dispatch_request("POST", "/api/v0/config", body, st);
  return r.code == 400 || (r.code == 401 && r.body.indexOf("ERR_CONFIG_SIGNATURE") >= 0);
}

bool test_config_post_rejects_empty_time_servers_entry(Context& ctx) {
  String fp;
  if (!compute_test_admin_ed25519_fp(fp)) return false;

  azt::AppState st{};
  st.managed = false;

  JsonDocument doc;
  doc["config_version"] = 1;
  doc["device_label"] = "dev";
  doc["admin_key"]["alg"] = "ed25519";
  doc["admin_key"]["public_key_b64"] = kTestAdminEd25519PublicKeyB64;
  doc["admin_key"]["fingerprint_alg"] = "sha256-raw-ed25519-pub";
  doc["admin_key"]["fingerprint_hex"] = fp;
  doc["wifi"]["ssid"] = "s";
  doc["wifi"]["password"] = "p";
  JsonArray servers = doc["time"]["servers"].to<JsonArray>();
  servers.add("pool.ntp.org");
  servers.add("  ");

  String body;
  serializeJson(doc, body);
  auto r = azt::dispatch_request("POST", "/api/v0/config", body, st);
  return r.code == 400 || (r.code == 401 && r.body.indexOf("ERR_CONFIG_SIGNATURE") >= 0);
}

bool test_config_post_rejects_non_string_time_servers_entry(Context& ctx) {
  String fp;
  if (!compute_test_admin_ed25519_fp(fp)) return false;

  azt::AppState st{};
  st.managed = false;

  JsonDocument doc;
  doc["config_version"] = 1;
  doc["device_label"] = "dev";
  doc["admin_key"]["alg"] = "ed25519";
  doc["admin_key"]["public_key_b64"] = kTestAdminEd25519PublicKeyB64;
  doc["admin_key"]["fingerprint_alg"] = "sha256-raw-ed25519-pub";
  doc["admin_key"]["fingerprint_hex"] = fp;
  doc["wifi"]["ssid"] = "s";
  doc["wifi"]["password"] = "p";
  JsonArray servers = doc["time"]["servers"].to<JsonArray>();
  servers.add("pool.ntp.org");
  servers.add(123);

  String body;
  serializeJson(doc, body);
  auto r = azt::dispatch_request("POST", "/api/v0/config", body, st);
  return r.code == 400 || (r.code == 401 && r.body.indexOf("ERR_CONFIG_SIGNATURE") >= 0);
}

bool test_config_post_rejects_non_string_authorized_listener_entry(Context& ctx) {
  String fp;
  if (!compute_test_admin_ed25519_fp(fp)) return false;

  azt::AppState st{};
  st.managed = false;

  JsonDocument doc;
  doc["config_version"] = 1;
  doc["device_label"] = "dev";
  doc["admin_key"]["alg"] = "ed25519";
  doc["admin_key"]["public_key_b64"] = kTestAdminEd25519PublicKeyB64;
  doc["admin_key"]["fingerprint_alg"] = "sha256-raw-ed25519-pub";
  doc["admin_key"]["fingerprint_hex"] = fp;
  JsonArray ips = doc["authorized_listener_ips"].to<JsonArray>();
  ips.add("192.168.1.10");
  ips.add(123);
  doc["wifi"]["ssid"] = "s";
  doc["wifi"]["password"] = "p";
  doc["time"]["server"] = "pool.ntp.org";

  String body;
  serializeJson(doc, body);
  auto r = azt::dispatch_request("POST", "/api/v0/config", body, st);
  return r.code == 400 || (r.code == 401 && r.body.indexOf("ERR_CONFIG_SIGNATURE") >= 0);
}

static JsonDocument build_base_config_doc(const String& pub_pem, const String& fp) {
  JsonDocument doc;
  String rec_fp;
  if (!azt::compute_pubkey_spki_sha256_hex(pub_pem, rec_fp)) rec_fp = "";
  doc["config_version"] = 1;
  doc["device_label"] = "dev";
  doc["admin_key"]["alg"] = "ed25519";
  doc["admin_key"]["public_key_b64"] = kTestAdminEd25519PublicKeyB64;
  doc["admin_key"]["fingerprint_alg"] = "sha256-raw-ed25519-pub";
  doc["admin_key"]["fingerprint_hex"] = fp;
  doc["listener_key"]["alg"] = "rsa-oaep-sha256";
  doc["listener_key"]["public_key_pem"] = pub_pem;
  doc["listener_key"]["fingerprint_alg"] = "sha256-spki-der";
  doc["listener_key"]["fingerprint_hex"] = rec_fp;
  doc["wifi"]["ssid"] = "s";
  doc["wifi"]["password"] = "p";
  doc["time"]["server"] = "pool.ntp.org";
  return doc;
}

bool test_config_post_rejects_invalid_audio_sample_rate(Context& ctx) {
  String fp;
  if (!compute_test_admin_ed25519_fp(fp)) return false;

  azt::AppState st{};
  st.managed = false;
  JsonDocument doc = build_base_config_doc(*ctx.pubkey_pem, fp);
  doc["audio"]["sample_rate_hz"] = 8000;
  doc["audio"]["channels"] = 1;
  doc["audio"]["sample_width_bytes"] = 2;

  String body;
  serializeJson(doc, body);
  auto r = azt::dispatch_request("POST", "/api/v0/config", body, st);
  return r.code == 401 && r.body.indexOf("ERR_CONFIG_SIGNATURE") >= 0 &&
         r.body.indexOf("ERR_CONFIG_SCHEMA") < 0;
}

bool test_config_post_rejects_invalid_audio_channels(Context& ctx) {
  String fp;
  if (!compute_test_admin_ed25519_fp(fp)) return false;

  azt::AppState st{};
  st.managed = false;
  JsonDocument doc = build_base_config_doc(*ctx.pubkey_pem, fp);
  doc["audio"]["sample_rate_hz"] = 16000;
  doc["audio"]["channels"] = 2;
  doc["audio"]["sample_width_bytes"] = 2;

  String body;
  serializeJson(doc, body);
  auto r = azt::dispatch_request("POST", "/api/v0/config", body, st);
  return r.code == 401 && r.body.indexOf("ERR_CONFIG_SIGNATURE") >= 0 &&
         r.body.indexOf("ERR_CONFIG_SCHEMA") < 0;
}

bool test_config_post_rejects_invalid_audio_sample_width(Context& ctx) {
  String fp;
  if (!compute_test_admin_ed25519_fp(fp)) return false;

  azt::AppState st{};
  st.managed = false;
  JsonDocument doc = build_base_config_doc(*ctx.pubkey_pem, fp);
  doc["audio"]["sample_rate_hz"] = 16000;
  doc["audio"]["channels"] = 1;
  doc["audio"]["sample_width_bytes"] = 1;

  String body;
  serializeJson(doc, body);
  auto r = azt::dispatch_request("POST", "/api/v0/config", body, st);
  return r.code == 401 && r.body.indexOf("ERR_CONFIG_SIGNATURE") >= 0 &&
         r.body.indexOf("ERR_CONFIG_SCHEMA") < 0;
}

bool test_config_state_includes_config_revision(Context&) {
  azt::AppState st{};
  st.managed = true;
  st.signed_config_ready = true;
  st.admin_fingerprint_hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
  st.device_sign_public_key_b64 = "AAAA";
  st.device_sign_fingerprint_hex = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
  st.config_revision = 7;

  auto r_state = azt::dispatch_request("GET", "/api/v0/config/state", "", st);
  return r_state.code == 200 && r_state.body.indexOf("\"config_revision\":7") >= 0;
}

bool test_config_patch_rejects_unset_admin(Context&) {
  azt::AppState st{};
  st.managed = false;
  auto r = azt::dispatch_request("POST", "/api/v0/config/patch", "{}", st);
  return r.code == 409 && r.body.indexOf("ERR_CONFIG_PATCH_UNSET_ADMIN") >= 0;
}

bool test_config_patch_rejects_invalid_json(Context&) {
  azt::AppState st{};
  st.managed = true;
  auto r = azt::dispatch_request("POST", "/api/v0/config/patch", "{not-json", st);
  return r.code == 400 && r.body.indexOf("ERR_CONFIG_SCHEMA") >= 0;
}

bool test_config_patch_requires_config_version_1(Context&) {
  azt::AppState st{};
  st.managed = true;
  JsonDocument doc;
  doc["config_version"] = 2;
  doc["if_version"] = 0;
  JsonObject p = doc["patch"].to<JsonObject>();
  p["device_label"] = "x";
  String body;
  serializeJson(doc, body);
  auto r = azt::dispatch_request("POST", "/api/v0/config/patch", body, st);
  return r.code == 400 || (r.code == 401 && r.body.indexOf("ERR_CONFIG_SIGNATURE") >= 0);
}

bool test_config_patch_rejects_version_conflict(Context&) {
  azt::AppState st{};
  st.managed = true;
  st.config_revision = 3;
  JsonDocument doc;
  doc["config_version"] = 1;
  doc["if_version"] = 1;
  JsonObject p = doc["patch"].to<JsonObject>();
  p["device_label"] = "x";
  String body;
  serializeJson(doc, body);
  auto r = azt::dispatch_request("POST", "/api/v0/config/patch", body, st);
  return r.code == 409 && r.body.indexOf("ERR_CONFIG_VERSION_CONFLICT") >= 0;
}

bool test_config_patch_forbids_admin_key_and_ota_fields(Context&) {
  azt::AppState st{};
  st.managed = true;
  st.config_revision = 0;
  JsonDocument doc;
  doc["config_version"] = 1;
  doc["if_version"] = 0;
  doc["ota_signer_clear"] = true;
  JsonObject p = doc["patch"].to<JsonObject>();
  p["device_label"] = "x";
  String body;
  serializeJson(doc, body);
  auto r = azt::dispatch_request("POST", "/api/v0/config/patch", body, st);
  return r.code == 403 && r.body.indexOf("ERR_PATCH_PATH_FORBIDDEN") >= 0;
}

bool test_config_patch_requires_signature(Context& ctx) {
  String fp;
  if (!compute_test_admin_ed25519_fp(fp)) return false;

  azt::AppState st{};
  st.managed = true;
  st.config_revision = 0;
  st.admin_pubkey_pem = kTestAdminEd25519PublicKeyB64;
  st.admin_fingerprint_hex = fp;

  JsonDocument doc;
  doc["config_version"] = 1;
  doc["if_version"] = 0;
  JsonObject p = doc["patch"].to<JsonObject>();
  p["device_label"] = "x";
  String body;
  serializeJson(doc, body);
  auto r = azt::dispatch_request("POST", "/api/v0/config/patch", body, st);
  return r.code == 401 && r.body.indexOf("ERR_CONFIG_SIGNATURE") >= 0;
}

bool test_certificate_post_invalid_json(Context&) {
  azt::AppState st{};
  auto r = azt::dispatch_request("POST", "/api/v0/device/certificate", "{bad-json", st);
  return r.code == 400 && r.body.indexOf("ERR_CERT_SCHEMA") >= 0;
}

bool test_certificate_post_missing_fields(Context&) {
  azt::AppState st{};
  auto r = azt::dispatch_request("POST", "/api/v0/device/certificate", "{}", st);
  return r.code == 400 && r.body.indexOf("ERR_CERT_SCHEMA") >= 0 &&
         r.body.indexOf("missing certificate_payload_b64/signature fields") >= 0;
}

static String build_cert_envelope_body(const String& dev_pub,
                                       const String& dev_fp,
                                       const String& admin_fp,
                                       const String& cert_serial,
                                       const String& signature_b64 = "AAAA") {
  JsonDocument payload;
  payload["certificate_version"] = 1;
  payload["certificate_type"] = "device_key_binding";
  payload["device_sign_public_key_b64"] = dev_pub;
  payload["device_sign_fingerprint_hex"] = dev_fp;
  payload["admin_signer_fingerprint_hex"] = admin_fp;
  payload["certificate_serial"] = cert_serial;
  payload["signature_algorithm"] = "ed25519";

  String payload_json;
  serializeJson(payload, payload_json);

  JsonDocument doc;
  doc["certificate_payload_b64"] = azt::b64(reinterpret_cast<const uint8_t*>(payload_json.c_str()), payload_json.length());
  doc["signature_algorithm"] = "ed25519";
  doc["signature_b64"] = signature_b64;

  String body;
  serializeJson(doc, body);
  return body;
}

bool test_certificate_post_invalid_payload_b64(Context&) {
  azt::AppState st{};
  JsonDocument doc;
  doc["certificate_payload_b64"] = "not-base64";
  doc["signature_algorithm"] = "ed25519";
  doc["signature_b64"] = "AAAA";
  String body;
  serializeJson(doc, body);
  auto r = azt::dispatch_request("POST", "/api/v0/device/certificate", body, st);
  return r.code == 400 && r.body.indexOf("ERR_CERT_PAYLOAD_B64") >= 0;
}

bool test_certificate_post_payload_json_invalid(Context&) {
  azt::AppState st{};
  JsonDocument doc;
  const char bad_payload[] = "{bad-json";
  doc["certificate_payload_b64"] = azt::b64(reinterpret_cast<const uint8_t*>(bad_payload), sizeof(bad_payload) - 1);
  doc["signature_algorithm"] = "ed25519";
  doc["signature_b64"] = "AAAA";
  String body;
  serializeJson(doc, body);
  auto r = azt::dispatch_request("POST", "/api/v0/device/certificate", body, st);
  return r.code == 400 && r.body.indexOf("ERR_CERT_PAYLOAD_JSON") >= 0;
}

bool test_certificate_post_device_mismatch(Context&) {
  azt::AppState st{};
  st.device_sign_public_key_b64 = "DEVICE_KEY_A";
  st.device_sign_fingerprint_hex = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
  st.admin_fingerprint_hex = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

  String body = build_cert_envelope_body("DEVICE_KEY_B",
                                         st.device_sign_fingerprint_hex,
                                         st.admin_fingerprint_hex,
                                         "cert-dev-mismatch");
  auto r = azt::dispatch_request("POST", "/api/v0/device/certificate", body, st);
  return r.code == 400 && r.body.indexOf("ERR_CERT_DEVICE_MISMATCH") >= 0;
}

bool test_certificate_post_admin_mismatch(Context&) {
  azt::AppState st{};
  st.device_sign_public_key_b64 = "DEVICE_KEY_A";
  st.device_sign_fingerprint_hex = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
  st.admin_fingerprint_hex = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

  String body = build_cert_envelope_body(st.device_sign_public_key_b64,
                                         st.device_sign_fingerprint_hex,
                                         "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                                         "cert-admin-mismatch");
  auto r = azt::dispatch_request("POST", "/api/v0/device/certificate", body, st);
  return r.code == 401 && r.body.indexOf("ERR_CERT_ADMIN_MISMATCH") >= 0;
}

bool test_certificate_post_admin_not_configured(Context&) {
  azt::AppState st{};
  st.device_sign_public_key_b64 = "DEVICE_KEY_A";
  st.device_sign_fingerprint_hex = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
  st.admin_fingerprint_hex = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
  st.admin_pubkey_pem = "";

  String body = build_cert_envelope_body(st.device_sign_public_key_b64,
                                         st.device_sign_fingerprint_hex,
                                         st.admin_fingerprint_hex,
                                         "cert-admin-not-configured");
  auto r = azt::dispatch_request("POST", "/api/v0/device/certificate", body, st);
  return r.code == 500 && r.body.indexOf("ERR_CERT_ADMIN_NOT_CONFIGURED") >= 0;
}

bool test_certificate_post_admin_fp_invalid(Context& ctx) {
  String fp;
  if (!compute_test_admin_ed25519_fp(fp)) return false;

  azt::AppState st{};
  st.device_sign_public_key_b64 = "DEVICE_KEY_A";
  st.device_sign_fingerprint_hex = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
  st.admin_fingerprint_hex = fp;
  st.admin_pubkey_pem = "NOT_B64";  // force admin key parse/hash failure

  String body = build_cert_envelope_body(st.device_sign_public_key_b64,
                                         st.device_sign_fingerprint_hex,
                                         st.admin_fingerprint_hex,
                                         "cert-admin-fp-invalid");
  auto r = azt::dispatch_request("POST", "/api/v0/device/certificate", body, st);
  return r.code == 400 && r.body.indexOf("ERR_CERT_ADMIN_FP") >= 0;
}

bool test_certificate_post_signature_verify_fail(Context& ctx) {
  String fp;
  if (!compute_test_admin_ed25519_fp(fp)) return false;

  azt::AppState st{};
  st.device_sign_public_key_b64 = "DEVICE_KEY_A";
  st.device_sign_fingerprint_hex = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
  st.admin_fingerprint_hex = fp;
  st.admin_pubkey_pem = kTestAdminEd25519PublicKeyB64;

  String body = build_cert_envelope_body(st.device_sign_public_key_b64,
                                         st.device_sign_fingerprint_hex,
                                         st.admin_fingerprint_hex,
                                         "cert-sig-verify-fail");
  auto r = azt::dispatch_request("POST", "/api/v0/device/certificate", body, st);
  return (r.code == 401 && r.body.indexOf("ERR_CERT_SIG_VERIFY") >= 0) || (r.code == 400 && r.body.indexOf("ERR_CERT_SCHEMA") >= 0);
}

bool test_certificate_post_signature_b64_invalid(Context& ctx) {
  String fp;
  if (!compute_test_admin_ed25519_fp(fp)) return false;

  azt::AppState st{};
  st.device_sign_public_key_b64 = "DEVICE_KEY_A";
  st.device_sign_fingerprint_hex = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
  st.admin_fingerprint_hex = fp;
  st.admin_pubkey_pem = kTestAdminEd25519PublicKeyB64;

  String body = build_cert_envelope_body(st.device_sign_public_key_b64,
                                         st.device_sign_fingerprint_hex,
                                         st.admin_fingerprint_hex,
                                         "cert-sig-b64-invalid",
                                         "@@not-b64@@");
  auto r = azt::dispatch_request("POST", "/api/v0/device/certificate", body, st);
  return (r.code == 401 && r.body.indexOf("ERR_CERT_SIG_VERIFY") >= 0) || (r.code == 400 && r.body.indexOf("ERR_CERT_SCHEMA") >= 0);
}

bool test_certificate_post_signature_algorithm_wrong(Context&) {
  JsonDocument doc;
  doc["certificate_payload_b64"] = "AAAA";
  doc["signature_algorithm"] = "rsa-pss-sha256";
  doc["signature_b64"] = "AAAA";
  String body;
  serializeJson(doc, body);

  azt::AppState st{};
  auto r = azt::dispatch_request("POST", "/api/v0/device/certificate", body, st);
  return r.code == 400 && r.body.indexOf("ERR_CERT_SCHEMA") >= 0;
}

bool test_certificate_post_missing_signature_b64(Context&) {
  JsonDocument doc;
  doc["certificate_payload_b64"] = "AAAA";
  doc["signature_algorithm"] = "ed25519";
  doc["signature_b64"] = "";
  String body;
  serializeJson(doc, body);

  azt::AppState st{};
  auto r = azt::dispatch_request("POST", "/api/v0/device/certificate", body, st);
  return r.code == 400 && r.body.indexOf("ERR_CERT_SCHEMA") >= 0;
}

bool test_certificate_post_missing_device_fields(Context&) {
  JsonDocument payload;
  payload["admin_signer_fingerprint_hex"] = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
  payload["certificate_serial"] = "cert-missing-device-fields";
  payload["signature_algorithm"] = "ed25519";
  String payload_json;
  serializeJson(payload, payload_json);

  JsonDocument doc;
  doc["certificate_payload_b64"] = azt::b64(reinterpret_cast<const uint8_t*>(payload_json.c_str()), payload_json.length());
  doc["signature_algorithm"] = "ed25519";
  doc["signature_b64"] = "AAAA";
  String body;
  serializeJson(doc, body);

  azt::AppState st{};
  st.device_sign_public_key_b64 = "DEVICE_KEY_A";
  st.device_sign_fingerprint_hex = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
  st.admin_fingerprint_hex = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
  auto r = azt::dispatch_request("POST", "/api/v0/device/certificate", body, st);
  return r.code == 400 && r.body.indexOf("ERR_CERT_DEVICE_MISMATCH") >= 0;
}

bool test_certificate_post_missing_admin_field(Context&) {
  JsonDocument payload;
  payload["device_sign_public_key_b64"] = "DEVICE_KEY_A";
  payload["device_sign_fingerprint_hex"] = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
  payload["certificate_serial"] = "cert-missing-admin-field";
  payload["signature_algorithm"] = "ed25519";
  String payload_json;
  serializeJson(payload, payload_json);

  JsonDocument doc;
  doc["certificate_payload_b64"] = azt::b64(reinterpret_cast<const uint8_t*>(payload_json.c_str()), payload_json.length());
  doc["signature_algorithm"] = "ed25519";
  doc["signature_b64"] = "AAAA";
  String body;
  serializeJson(doc, body);

  azt::AppState st{};
  st.device_sign_public_key_b64 = "DEVICE_KEY_A";
  st.device_sign_fingerprint_hex = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
  st.admin_fingerprint_hex = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
  auto r = azt::dispatch_request("POST", "/api/v0/device/certificate", body, st);
  return r.code == 401 && r.body.indexOf("ERR_CERT_ADMIN_MISMATCH") >= 0;
}

bool test_serial_control_parse_begin_len_invalid_and_valid(Context&) {
  azt::SerialControlState st{};
  size_t out_len = 0;
  String out_err;

  bool consumed_bad = azt::parse_config_begin_len_command("AZT_CONFIG_BEGIN_LEN 70000", 100, st, out_len, out_err, 64 * 1024);
  if (!consumed_bad) return false;
  if (out_err.indexOf("AZT_CONFIG_BEGIN_LEN ERR") < 0) return false;
  if (st.config_mode || st.config_len_mode) return false;

  out_err = "";
  bool consumed_ok = azt::parse_config_begin_len_command("AZT_CONFIG_BEGIN_LEN 123", 200, st, out_len, out_err, 64 * 1024);
  if (!consumed_ok || out_err.length() != 0) return false;
  return st.config_mode && st.config_len_mode && st.config_expected_len == 123 && st.config_last_rx_ms == 200 && out_len == 123;
}

bool test_serial_control_timeout_and_clear(Context&) {
  azt::SerialControlState st{};
  st.config_mode = true;
  st.config_len_mode = true;
  st.config_expected_len = 10;
  st.config_last_rx_ms = 100;
  st.config_buf = "abc";

  if (azt::is_serial_config_rx_timed_out(st, 30100, 30000)) return false;
  if (!azt::is_serial_config_rx_timed_out(st, 30101, 30000)) return false;

  azt::clear_serial_config_rx_state(st);
  return !st.config_mode && !st.config_len_mode && st.config_expected_len == 0 && st.config_last_rx_ms == 0 && st.config_buf.length() == 0;
}

bool test_serial_control_config_mode_framing_resets_state(Context&) {
  azt::SerialControlState st{};
  st.config_mode = true;
  st.config_len_mode = true;
  st.config_expected_len = 50;
  st.config_last_rx_ms = 123;
  st.config_buf = "partial";

  String line = azt::handle_config_mode_line_command("AZT_CONFIG_END", st);
  if (line.indexOf("ERR_CONFIG_FRAMING") < 0) return false;
  return !st.config_mode && !st.config_len_mode && st.config_expected_len == 0 && st.config_last_rx_ms == 0 && st.config_buf.length() == 0;
}

bool test_serial_control_recovery_and_lock_error_lines(Context&) {
  String lock_err = azt::format_config_apply_lock_error_line();
  if (lock_err.indexOf("ERR_STATE_LOCK") < 0) return false;

  String rec_lock = azt::format_recovery_reset_result_line(false, false);
  String rec_ok = azt::format_recovery_reset_result_line(true, true);
  String rec_err = azt::format_recovery_reset_result_line(true, false);

  return rec_lock == "AZT_RECOVERY_RESET_CONFIG ERR_LOCK" &&
         rec_ok == "AZT_RECOVERY_RESET_CONFIG OK" &&
         rec_err == "AZT_RECOVERY_RESET_CONFIG ERR";
}

bool test_serial_control_consume_payload_reaches_expected_len(Context&) {
  azt::SerialControlState st{};
  st.config_mode = true;
  st.config_len_mode = true;
  st.config_expected_len = 5;
  st.config_last_rx_ms = 100;

  auto step1 = azt::consume_config_payload_chunk(st, "abc", 110, 30000);
  if (step1.reached_expected_len || step1.timed_out) return false;
  if (st.config_buf != "abc" || st.config_last_rx_ms != 110) return false;

  auto step2 = azt::consume_config_payload_chunk(st, "def", 120, 30000);
  return step2.reached_expected_len && !step2.timed_out && st.config_buf == "abcde";
}

bool test_serial_control_consume_payload_timeout(Context&) {
  azt::SerialControlState st{};
  st.config_mode = true;
  st.config_len_mode = true;
  st.config_expected_len = 10;
  st.config_last_rx_ms = 100;
  st.config_buf = "abc";

  auto step = azt::consume_config_payload_chunk(st, "", 30101, 30000);
  return !step.reached_expected_len && step.timed_out;
}

bool test_serial_control_classify_command(Context&) {
  if (azt::classify_serial_command("AZT_CONFIG_BEGIN_LEN 10") != azt::SerialCommandKind::kConfigBeginLen) return false;
  if (azt::classify_serial_command("AZT_CONFIG_BEGIN") != azt::SerialCommandKind::kConfigBeginLegacy) return false;
  if (azt::classify_serial_command("AZT_RECOVERY_RESET_CONFIG") != azt::SerialCommandKind::kRecoveryReset) return false;
  return azt::classify_serial_command("NOOP") == azt::SerialCommandKind::kUnknown;
}

bool test_device_io_has_wifi_credentials(Context&) {
  azt::AppState st{};
  st.wifi_ssid = "ssid";
  st.wifi_pass = "pass";
  if (!azt::has_wifi_credentials(st)) return false;

  st.wifi_pass = "";
  if (azt::has_wifi_credentials(st)) return false;

  st.wifi_ssid = "";
  st.wifi_pass = "pass";
  return !azt::has_wifi_credentials(st);
}

bool test_device_io_wifi_status_helpers(Context&) {
  if (!azt::is_wifi_connected_status(WL_CONNECTED)) return false;
  if (azt::is_wifi_connected_status(WL_IDLE_STATUS)) return false;

  azt::AppState st{};
  azt::record_wifi_connect_result(st, "state-reconnect", WL_CONNECTED);
  if (st.wifi_last_connect_source != "state-reconnect") return false;
  if (st.wifi_last_status != WL_CONNECTED) return false;

  azt::record_wifi_connect_result(st, "state-change", WL_IDLE_STATUS);
  return st.wifi_last_connect_source == "state-change" && st.wifi_last_status == WL_IDLE_STATUS;
}

bool test_device_io_decide_wifi_maintain(Context&) {
  azt::AppState st{};
  st.wifi_ssid = "s";
  st.wifi_pass = "p";

  if (azt::decide_wifi_maintain(st, "s", "p", WL_CONNECTED, 1000, 900, 5000) !=
      azt::WifiMaintainDecision::kSkipInterval) return false;

  if (azt::decide_wifi_maintain(st, "old", "p", WL_CONNECTED, 6000, 0, 5000) !=
      azt::WifiMaintainDecision::kReconnectStateChange) return false;

  if (azt::decide_wifi_maintain(st, "s", "p", WL_CONNECTED, 6000, 0, 5000) !=
      azt::WifiMaintainDecision::kSkipAlreadyConnected) return false;

  if (azt::decide_wifi_maintain(st, "s", "p", WL_IDLE_STATUS, 6000, 0, 5000) !=
      azt::WifiMaintainDecision::kReconnectStateRetry) return false;

  st.wifi_pass = "";
  return azt::decide_wifi_maintain(st, "s", "p", WL_IDLE_STATUS, 6000, 0, 5000) ==
         azt::WifiMaintainDecision::kSkipNoCreds;
}

bool test_device_io_wifi_connect_decision_helpers(Context&) {
  if (!azt::should_attempt_wifi_connect(azt::WifiMaintainDecision::kReconnectStateChange)) return false;
  if (!azt::should_attempt_wifi_connect(azt::WifiMaintainDecision::kReconnectStateRetry)) return false;
  if (azt::should_attempt_wifi_connect(azt::WifiMaintainDecision::kSkipAlreadyConnected)) return false;
  if (!azt::should_emit_wifi_timeout_log(false)) return false;
  if (azt::should_emit_wifi_timeout_log(true)) return false;

  return String(azt::wifi_connect_source_for_decision(azt::WifiMaintainDecision::kReconnectStateChange)) == "state-change" &&
         String(azt::wifi_connect_source_for_decision(azt::WifiMaintainDecision::kReconnectStateRetry)) == "state-reconnect";
}

bool test_device_io_setup_wifi_result(Context&) {
  if (azt::evaluate_setup_wifi_result(false, false) != azt::WifiSetupResult::kNotConfigured) return false;
  if (azt::evaluate_setup_wifi_result(true, true) != azt::WifiSetupResult::kConnected) return false;
  if (azt::evaluate_setup_wifi_result(true, false) != azt::WifiSetupResult::kTimeout) return false;

  if (azt::should_attempt_setup_wifi_connect(false)) return false;
  return azt::should_attempt_setup_wifi_connect(true);
}

bool test_device_io_make_wifi_maintain_plan(Context&) {
  auto p_skip_interval = azt::make_wifi_maintain_plan(azt::WifiMaintainDecision::kSkipInterval);
  if (p_skip_interval.should_update_cache) return false;
  if (p_skip_interval.should_connect) return false;

  auto p_skip_connected = azt::make_wifi_maintain_plan(azt::WifiMaintainDecision::kSkipAlreadyConnected);
  if (!p_skip_connected.should_update_cache) return false;
  if (p_skip_connected.should_connect) return false;

  auto p_change = azt::make_wifi_maintain_plan(azt::WifiMaintainDecision::kReconnectStateChange);
  if (!p_change.should_update_cache || !p_change.should_connect) return false;
  if (String(p_change.connect_source) != "state-change") return false;

  auto p_retry = azt::make_wifi_maintain_plan(azt::WifiMaintainDecision::kReconnectStateRetry);
  return p_retry.should_update_cache && p_retry.should_connect && String(p_retry.connect_source) == "state-reconnect";
}

bool test_device_io_update_wifi_maintain_cache(Context&) {
  azt::AppState st{};
  st.wifi_ssid = "ssid-a";
  st.wifi_pass = "pass-a";

  uint32_t last_ms = 0;
  String last_ssid;
  String last_pass;
  azt::update_wifi_maintain_cache(st, 1234, last_ms, last_ssid, last_pass);
  if (last_ms != 1234 || last_ssid != "ssid-a" || last_pass != "pass-a") return false;

  st.wifi_ssid = "ssid-b";
  st.wifi_pass = "pass-b";
  azt::update_wifi_maintain_cache(st, 5678, last_ms, last_ssid, last_pass);
  return last_ms == 5678 && last_ssid == "ssid-b" && last_pass == "pass-b";
}

bool test_device_io_extract_time_servers_csv(Context&) {
  String out[3];
  int n = azt::extract_time_servers_csv("pool.ntp.org, time.google.com , ,time.cloudflare.com,extra", out);
  return n == 3 &&
         out[0] == "pool.ntp.org" &&
         out[1] == "time.google.com" &&
         out[2] == "time.cloudflare.com";
}

bool test_device_io_should_skip_time_sync(Context&) {
  if (!azt::should_skip_time_sync(WL_IDLE_STATUS, "pool.ntp.org")) return false;
  if (!azt::should_skip_time_sync(WL_CONNECTED, "")) return false;
  return !azt::should_skip_time_sync(WL_CONNECTED, "pool.ntp.org");
}

bool test_device_io_choose_sntp_start_action(Context&) {
  return azt::choose_sntp_start_action(true) == azt::SntpStartAction::kRestart &&
         azt::choose_sntp_start_action(false) == azt::SntpStartAction::kInit;
}

}  // namespace

void register_test_azt_http_api(Registry& out) {
  out.push_back({"PARSE_REQUEST_LINE", test_parse_request_line, "request-line parser mismatch"});
  out.push_back({"PARSE_REQUEST_LINE_MULTIPLE_SPACES", test_parse_request_line_multiple_spaces, "request-line parser should tolerate repeated spaces"});
  out.push_back({"PARSE_REQUEST_LINE_MISSING_PATH", test_parse_request_line_missing_path, "request-line parser should reject missing path"});
  out.push_back({"PARSE_REQUEST_LINE_EMPTY_METHOD", test_parse_request_line_empty_method, "request-line parser should reject empty method"});
  out.push_back({"PARSE_REQUEST_LINE_PATH_ONLY", test_parse_request_line_path_only, "request-line parser should reject path-only line"});
  out.push_back({"PARSE_REQUEST_LINE_REQUIRES_HTTP_VERSION", test_parse_request_line_requires_http_version, "request-line parser should require method/path/version tokens"});
  out.push_back({"PARSE_REQUEST_LINE_ACCEPTS_TABS_AND_TRIM", test_parse_request_line_accepts_tabs_and_trim, "request-line parser should tolerate tabs and outer whitespace"});
  out.push_back({"PARSE_REQUEST_LINE_REJECTS_NON_SLASH_PATH", test_parse_request_line_rejects_non_slash_path, "request-line parser should require absolute path token"});
  out.push_back({"PARSE_REQUEST_LINE_REJECTS_EXTRA_TOKEN", test_parse_request_line_rejects_extra_token, "request-line parser should reject unexpected trailing token"});
  out.push_back({"UPGRADE_GET_ROUTE_RETURNS_UPLOAD_UI", test_upgrade_get_route_returns_upload_ui, "upgrade GET route should return OTA upload HTML UI"});
  out.push_back({"OTA_BUNDLE_HEADER_VALIDATION_INVALID_KIND", test_ota_bundle_header_validation_invalid_kind, "ota bundle header validator should reject invalid kind"});
  out.push_back({"OTA_BUNDLE_HEADER_VALIDATION_MISSING_FIELDS", test_ota_bundle_header_validation_missing_fields, "ota bundle header validator should reject missing signed fields"});
  out.push_back({"OTA_BUNDLE_HEADER_VALIDATION_SUCCESS", test_ota_bundle_header_validation_success, "ota bundle header validator should accept valid header"});
  out.push_back({"OTA_FIRMWARE_META_VALIDATION", test_ota_firmware_meta_validation, "ota firmware meta validator should enforce required fields"});
  out.push_back({"OTA_BUNDLE_PAYLOAD_LENGTHS_VALIDATION", test_ota_bundle_payload_lengths_validation, "ota bundle payload length validator mismatch"});
  out.push_back({"OTA_TRAILING_DRAIN_HELPERS", test_ota_trailing_drain_helpers, "ota trailing drain helper behavior mismatch"});
  out.push_back({"OTA_TRANSPORT_ERROR_HELPERS", test_ota_transport_error_helpers, "ota transport error helper behavior mismatch"});
  out.push_back({"OTA_UPDATE_FLOW_ERROR_HELPERS", test_ota_update_flow_error_helpers, "ota update-flow error helper behavior mismatch"});
  out.push_back({"DISPATCH_REQUEST_BASIC_ROUTES", test_dispatch_request_basic_routes, "dispatch basic routes mismatch"});
  out.push_back({"PARSE_WIFI_VALUES", test_parse_wifi_values, "wifi parser mismatch"});
  out.push_back({"PARSE_HEADER_KEY_VALUES", test_parse_header_key_values, "header key parser mismatch"});
  out.push_back({"PARSE_HEADER_KEY_VALUES_MISSING_ADMIN_KEY", test_parse_header_key_values_missing_admin_key, "header key parser should reject missing admin_key"});
  out.push_back({"PARSE_HEADER_KEY_VALUES_WRONG_FINGERPRINT_ALG", test_parse_header_key_values_wrong_fingerprint_alg, "header key parser should enforce fingerprint_alg"});
  out.push_back({"PARSE_HEADER_KEY_VALUES_INVALID_FINGERPRINT_LENGTH", test_parse_header_key_values_invalid_fingerprint_length, "header key parser should enforce fingerprint length"});
  out.push_back({"PARSE_HEADER_KEY_VALUES_INVALID_PUBLIC_PEM", test_parse_header_key_values_invalid_public_pem, "header key parser should reject invalid PEM"});
  out.push_back({"CONFIG_POST_REQUIRES_SIGNATURE_UNMANAGED", test_config_post_requires_signature_unmanaged, "config post should require signature in unmanaged state"});
  out.push_back({"CONFIG_POST_REJECTS_OTA_SIGNER_OVERRIDE_VIA_API", test_config_post_rejects_ota_signer_override_via_api, "ota signer override should be rejected via HTTP API path"});
  out.push_back({"SIGNING_PUBLIC_KEY_ENDPOINT_PEM", test_signing_public_key_endpoint_pem, "signing-public-key endpoint should emit PEM"});
  out.push_back({"ATTESTATION_NONCE_TOO_SHORT", test_attestation_nonce_too_short, "attestation nonce bounds check mismatch"});
  out.push_back({"ATTESTATION_NONCE_MISSING", test_attestation_nonce_missing, "attestation should require nonce query param"});
  out.push_back({"STREAM_QUERY_TELEMETRY_TRUTHY_VARIANTS", test_stream_query_telemetry_truthy_variants, "stream telemetry truthy variant parsing mismatch"});
  out.push_back({"STREAM_QUERY_DROP_TEST_FRAMES_INVALID_DEFAULTS_ZERO", test_stream_query_drop_test_frames_invalid_defaults_zero, "invalid drop_test_frames values should default to zero"});
  out.push_back({"REBOOT_ENDPOINT_SETS_FLAG", test_reboot_endpoint_sets_flag, "reboot endpoint should set reboot-after-response flag"});
  out.push_back({"SIGNING_PUBLIC_KEY_ENDPOINT_ALIAS", test_signing_public_key_endpoint_alias, "signing-public-key alias endpoint should emit PEM"});
  out.push_back({"CONFIG_POST_REJECTS_INVALID_RECORDING_KEY", test_config_post_rejects_invalid_listener_key, "invalid listener_key object should be rejected"});
  out.push_back({"CONFIG_POST_REJECTS_INVALID_TIME", test_config_post_rejects_invalid_time, "invalid time config should be rejected"});
  out.push_back({"CONFIG_POST_REJECTS_INVALID_AUTH_LISTENER_IPS_TYPE", test_config_post_rejects_invalid_authorized_listener_ips_type, "authorized_listener_ips must be an array"});
  out.push_back({"CONFIG_POST_REJECTS_INVALID_AUTH_LISTENER_IP_VALUE", test_config_post_rejects_invalid_authorized_listener_ip_value, "authorized_listener_ips values must be valid IPv4"});
  out.push_back({"SIGNING_PUBLIC_KEY_ENDPOINT_INVALID_DEVICE_KEY", test_signing_public_key_endpoint_invalid_device_key, "invalid device signing key should fail PEM conversion"});
  out.push_back({"ATTESTATION_NONCE_TOO_LONG", test_attestation_nonce_too_long, "attestation nonce upper bound check mismatch"});
  out.push_back({"CONFIG_POST_INVALID_JSON", test_config_post_invalid_json, "invalid config JSON should be rejected"});
  out.push_back({"SIGNING_PUBLIC_KEY_ENDPOINT_MISSING_DEVICE_KEY", test_signing_public_key_endpoint_missing_device_key, "missing device signing key should fail PEM conversion"});
  out.push_back({"SIGNING_PUBLIC_KEY_ALIAS_INVALID_DEVICE_KEY", test_signing_public_key_alias_invalid_device_key, "signing key alias endpoint should fail on invalid device key"});
  out.push_back({"SIGNING_PUBLIC_KEY_ALIAS_MISSING_DEVICE_KEY", test_signing_public_key_alias_missing_device_key, "signing key alias endpoint should fail on missing device key"});
  out.push_back({"ATTESTATION_VALID_NONCE_REACHES_NON_SCHEMA_PATH", test_attestation_valid_nonce_reaches_non_schema_path, "valid attestation nonce should pass schema bounds"});
  out.push_back({"ATTESTATION_MAX_NONCE_LEN_SCHEMA_ACCEPTS", test_attestation_max_nonce_len_schema_accepts, "max-length nonce should pass schema bounds"});
  out.push_back({"CONFIG_POST_REJECTS_WRONG_VERSION", test_config_post_rejects_wrong_version, "config_version must be enforced"});
  out.push_back({"CONFIG_POST_REJECTS_MISSING_DEVICE_LABEL", test_config_post_rejects_missing_device_label, "device_label is required"});
  out.push_back({"CONFIG_POST_REJECTS_INVALID_WIFI_OBJECT", test_config_post_rejects_invalid_wifi_object, "wifi object must include non-empty ssid/password"});
  out.push_back({"CONFIG_POST_REJECTS_INVALID_ADMIN_KEY", test_config_post_rejects_invalid_admin_key, "invalid admin_key object should be rejected"});
  out.push_back({"CONFIG_POST_REQUIRES_SIGNATURE_MANAGED", test_config_post_requires_signature_managed, "managed config updates should require valid signature envelope"});
  out.push_back({"CONFIG_POST_REJECTS_EMPTY_TIME_SERVER", test_config_post_rejects_empty_time_server, "time.server must be non-empty"});
  out.push_back({"CONFIG_POST_REJECTS_EMPTY_TIME_SERVERS_ENTRY", test_config_post_rejects_empty_time_servers_entry, "time.servers entries must be non-empty"});
  out.push_back({"CONFIG_POST_REJECTS_NON_STRING_TIME_SERVERS_ENTRY", test_config_post_rejects_non_string_time_servers_entry, "time.servers entries must be strings"});
  out.push_back({"CONFIG_POST_REJECTS_NON_STRING_AUTH_LISTENER_ENTRY", test_config_post_rejects_non_string_authorized_listener_entry, "authorized_listener_ips entries must be strings"});
  out.push_back({"CONFIG_POST_REJECTS_INVALID_AUDIO_SAMPLE_RATE", test_config_post_rejects_invalid_audio_sample_rate, "audio sample rate must be 16000"});
  out.push_back({"CONFIG_POST_REJECTS_INVALID_AUDIO_CHANNELS", test_config_post_rejects_invalid_audio_channels, "audio channels must be mono"});
  out.push_back({"CONFIG_POST_REJECTS_INVALID_AUDIO_SAMPLE_WIDTH", test_config_post_rejects_invalid_audio_sample_width, "audio sample width must be 2 bytes"});
  out.push_back({"CONFIG_STATE_INCLUDES_CONFIG_REVISION", test_config_state_includes_config_revision, "config state should expose config_revision"});
  out.push_back({"CONFIG_PATCH_REJECTS_UNSET_ADMIN", test_config_patch_rejects_unset_admin, "config patch should reject when device is not managed"});
  out.push_back({"CONFIG_PATCH_REJECTS_INVALID_JSON", test_config_patch_rejects_invalid_json, "config patch should reject invalid json"});
  out.push_back({"CONFIG_PATCH_REQUIRES_CONFIG_VERSION_1", test_config_patch_requires_config_version_1, "config patch should enforce config_version=1"});
  out.push_back({"CONFIG_PATCH_REJECTS_VERSION_CONFLICT", test_config_patch_rejects_version_conflict, "config patch should reject stale if_version"});
  out.push_back({"CONFIG_PATCH_FORBIDS_ADMIN_KEY_AND_OTA_FIELDS", test_config_patch_forbids_admin_key_and_ota_fields, "config patch should forbid admin_key and ota signer fields"});
  out.push_back({"CONFIG_PATCH_REQUIRES_SIGNATURE", test_config_patch_requires_signature, "config patch should require signature envelope"});
  out.push_back({"CERTIFICATE_POST_INVALID_JSON", test_certificate_post_invalid_json, "certificate POST should reject invalid JSON"});
  out.push_back({"CERTIFICATE_POST_MISSING_FIELDS", test_certificate_post_missing_fields, "certificate POST should require envelope fields"});
  out.push_back({"CERTIFICATE_POST_INVALID_PAYLOAD_B64", test_certificate_post_invalid_payload_b64, "certificate POST should reject invalid payload base64"});
  out.push_back({"CERTIFICATE_POST_PAYLOAD_JSON_INVALID", test_certificate_post_payload_json_invalid, "certificate POST should reject invalid decoded payload JSON"});
  out.push_back({"CERTIFICATE_POST_DEVICE_MISMATCH", test_certificate_post_device_mismatch, "certificate POST should reject device key mismatch"});
  out.push_back({"CERTIFICATE_POST_ADMIN_MISMATCH", test_certificate_post_admin_mismatch, "certificate POST should reject admin fingerprint mismatch"});
  out.push_back({"CERTIFICATE_POST_ADMIN_NOT_CONFIGURED", test_certificate_post_admin_not_configured, "certificate POST should reject when admin signing key is not configured"});
  out.push_back({"CERTIFICATE_POST_ADMIN_FP_INVALID", test_certificate_post_admin_fp_invalid, "certificate POST should reject when admin PEM/fingerprint coherence fails"});
  out.push_back({"CERTIFICATE_POST_SIGNATURE_VERIFY_FAIL", test_certificate_post_signature_verify_fail, "certificate POST should reject invalid certificate signature"});
  out.push_back({"CERTIFICATE_POST_SIGNATURE_B64_INVALID", test_certificate_post_signature_b64_invalid, "certificate POST should reject invalid signature base64"});
  out.push_back({"CERTIFICATE_POST_SIGNATURE_ALGORITHM_WRONG", test_certificate_post_signature_algorithm_wrong, "certificate POST should require ed25519 signature_algorithm"});
  out.push_back({"CERTIFICATE_POST_MISSING_SIGNATURE_B64", test_certificate_post_missing_signature_b64, "certificate POST should require signature_b64"});
  out.push_back({"CERTIFICATE_POST_MISSING_DEVICE_FIELDS", test_certificate_post_missing_device_fields, "certificate payload missing device fields should mismatch"});
  out.push_back({"CERTIFICATE_POST_MISSING_ADMIN_FIELD", test_certificate_post_missing_admin_field, "certificate payload missing admin signer field should mismatch"});
  out.push_back({"SERIAL_CONTROL_PARSE_BEGIN_LEN_INVALID_AND_VALID", test_serial_control_parse_begin_len_invalid_and_valid, "serial control begin-len parsing should handle invalid and valid lengths"});
  out.push_back({"SERIAL_CONTROL_TIMEOUT_AND_CLEAR", test_serial_control_timeout_and_clear, "serial control timeout and clear-state behavior mismatch"});
  out.push_back({"SERIAL_CONTROL_CONFIG_MODE_FRAMING_RESETS_STATE", test_serial_control_config_mode_framing_resets_state, "serial control framing error should reset config receive state"});
  out.push_back({"SERIAL_CONTROL_RECOVERY_AND_LOCK_ERROR_LINES", test_serial_control_recovery_and_lock_error_lines, "serial control recovery/lock result formatting mismatch"});
  out.push_back({"SERIAL_CONTROL_CONSUME_PAYLOAD_REACHES_EXPECTED_LEN", test_serial_control_consume_payload_reaches_expected_len, "serial control payload consumer should clamp to expected length and report completion"});
  out.push_back({"SERIAL_CONTROL_CONSUME_PAYLOAD_TIMEOUT", test_serial_control_consume_payload_timeout, "serial control payload consumer should report timeout when stalled"});
  out.push_back({"SERIAL_CONTROL_CLASSIFY_COMMAND", test_serial_control_classify_command, "serial control command classification mismatch"});
  out.push_back({"DEVICE_IO_HAS_WIFI_CREDENTIALS", test_device_io_has_wifi_credentials, "device io wifi credential detection mismatch"});
  out.push_back({"DEVICE_IO_WIFI_STATUS_HELPERS", test_device_io_wifi_status_helpers, "device io wifi status/result helper behavior mismatch"});
  out.push_back({"DEVICE_IO_DECIDE_WIFI_MAINTAIN", test_device_io_decide_wifi_maintain, "device io wifi maintenance decision mismatch"});
  out.push_back({"DEVICE_IO_WIFI_CONNECT_DECISION_HELPERS", test_device_io_wifi_connect_decision_helpers, "device io wifi connect-decision helper behavior mismatch"});
  out.push_back({"DEVICE_IO_SETUP_WIFI_RESULT", test_device_io_setup_wifi_result, "device io setup wifi result classification mismatch"});
  out.push_back({"DEVICE_IO_MAKE_WIFI_MAINTAIN_PLAN", test_device_io_make_wifi_maintain_plan, "device io maintain-plan mapping mismatch"});
  out.push_back({"DEVICE_IO_UPDATE_WIFI_MAINTAIN_CACHE", test_device_io_update_wifi_maintain_cache, "device io maintain cache update mismatch"});
  out.push_back({"DEVICE_IO_EXTRACT_TIME_SERVERS_CSV", test_device_io_extract_time_servers_csv, "device io time server CSV extraction mismatch"});
  out.push_back({"DEVICE_IO_SHOULD_SKIP_TIME_SYNC", test_device_io_should_skip_time_sync, "device io time-sync skip decision mismatch"});
  out.push_back({"DEVICE_IO_CHOOSE_SNTP_START_ACTION", test_device_io_choose_sntp_start_action, "device io sntp start-action decision mismatch"});
}

}  // namespace azt_test
