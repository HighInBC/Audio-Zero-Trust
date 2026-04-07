#pragma once

#include <WiFiClient.h>
#include <ArduinoJson.h>

#include "azt_app_state.h"

namespace azt {

struct HttpDispatchResult {
  bool wants_stream = false;
  int stream_seconds = 0;
  bool stream_signbench_each_chunk = false;
  bool stream_enable_telemetry = false;
  int stream_drop_test_frames = 0;
  int code = 200;
  String body;
  String content_type = "application/json";
  bool reboot_after_response = false;
};

bool parse_wifi_values(JsonDocument& doc, String& ssid, String& pass);
bool parse_header_key_values(JsonDocument& doc, String& admin_pem, String& admin_fp);

bool parse_request_line(const String& req, String& method, String& path);
HttpDispatchResult dispatch_request(const String& method,
                                   const String& path,
                                   const String& body,
                                   AppState& state,
                                   const String& remote_ip = "");

// OTA upgrade validation helpers (deterministic unit-test targets).
bool validate_ota_bundle_header_line(const String& header_line,
                                     String& out_signer_fp,
                                     String& out_meta_b64,
                                     String& out_meta_sig_b64,
                                     String& out_err);
bool validate_ota_firmware_meta(const JsonDocument& meta,
                                int& out_fw_size,
                                String& out_fw_sha,
                                String& out_err);
bool validate_ota_bundle_payload_lengths(int content_len,
                                         int header_line_len,
                                         int fw_size,
                                         int& out_bytes_left,
                                         String& out_err);
bool should_drain_trailing_bundle_bytes(int bytes_left);
int ota_next_drain_chunk_size(int bytes_left, int buf_size);
bool ota_stream_read_failed(int n_read);
bool ota_update_write_mismatch(size_t wrote, int expected);
bool ota_begin_failed(bool begin_ok);
bool ota_sha_mismatch(const String& got_sha, const String& expected_sha);
bool ota_end_failed(bool end_ok);
bool ota_should_abort_on_error(bool has_error);

void handle_client(WiFiClient& client, AppState& state);
void handle_client_api_only(WiFiClient& client, AppState& state);
void handle_client_stream_only(WiFiClient& client, const AppState& state);

// Serial/bootstrap path for initial unsigned config application.
// Returns HTTP-like code and JSON body.
HttpDispatchResult apply_config_json_from_serial(AppState& state, const String& body);

// Serial-only OTA controls path (physical serial access is the trust boundary).
// Supports ota_version_code, ota_min_allowed_version_code, ota_min_allowed_version_code_clear,
// ota_signer_public_key_pem, ota_signer_clear.
HttpDispatchResult apply_ota_controls_json_from_serial(AppState& state, const String& body);

}  // namespace azt
