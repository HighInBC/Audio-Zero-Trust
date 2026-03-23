#pragma once

#include <Arduino.h>

namespace azt {

struct AppState {
  bool managed = false;
  bool signed_config_ready = false;
  String admin_pubkey_pem;
  String admin_fingerprint_hex;
  String recording_pubkey_pem;
  String recording_fingerprint_hex;
  String device_label;
  String wifi_ssid;
  String wifi_pass;
  String authorized_listener_ips_csv;
  String time_servers_csv;
  bool mdns_enabled = false;
  String mdns_hostname;
  String device_certificate_serial;
  String device_certificate_json;
  String discovery_announcement_json;

  // TLS server certificate state (certificate material is stored in prefs).
  String tls_certificate_serial;
  bool tls_server_cert_configured = false;
  bool tls_server_key_configured = false;
  bool tls_ca_cert_configured = false;

  // Runtime Wi-Fi diagnostics (non-secret)
  String wifi_last_connect_source;
  int wifi_last_status = 0;

  // Boot/reset diagnostics.
  uint32_t last_reset_reason_code = 0;
  String last_reset_reason;
  bool last_reset_unexpected = false;
  uint32_t unexpected_reset_count = 0;

  // Runtime time-sync diagnostics
  bool time_synced = false;
  uint32_t time_last_sync_epoch = 0;  // UTC seconds at last successful sync
  uint32_t time_last_sync_millis = 0; // millis() when sync succeeded

  // Hardware identity
  String device_chip_id_hex;

  // Device authenticity key material identity (Ed25519)
  String device_sign_public_key_b64;
  String device_sign_fingerprint_hex;

  // Optional OTA signer override (serial-configurable only).
  String ota_signer_override_public_key_pem;
  String ota_signer_override_fingerprint_hex;
  String last_ota_version;
  uint64_t last_ota_version_code = 0;
  uint64_t ota_min_allowed_version_code = 0;

  // Monotonic config revision for optimistic concurrency guards.
  uint32_t config_revision = 0;
};

}  // namespace azt
