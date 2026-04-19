#include "azt_discovery.h"

#include <ArduinoJson.h>
#include <WiFi.h>
#include <WiFiUdp.h>
#include <mbedtls/base64.h>
#include <vector>

namespace azt {

static constexpr uint16_t kDiscoveryPort = 33333;

static bool decode_cert_payload_json(const String& cert_json, JsonDocument& out_payload) {
  JsonDocument cert_doc;
  if (deserializeJson(cert_doc, cert_json) != DeserializationError::Ok) return false;
  String payload_b64 = String((const char*)(cert_doc["certificate_payload_b64"] | ""));
  if (payload_b64.length() == 0) return false;

  size_t out_len = 0;
  std::vector<uint8_t> raw(payload_b64.length());
  if (mbedtls_base64_decode(raw.data(), raw.size(), &out_len,
                            reinterpret_cast<const unsigned char*>(payload_b64.c_str()), payload_b64.length()) != 0) {
    return false;
  }
  raw.resize(out_len);

  if (deserializeJson(out_payload, raw.data(), raw.size()) != DeserializationError::Ok) return false;
  return true;
}

static void extract_discovery_cert_flags(const AppState& state, bool& out_auto_record, bool& out_auto_decode) {
  out_auto_record = false;
  out_auto_decode = false;
  if (state.device_certificate_json.length() == 0) return;

  JsonDocument payload;
  if (!decode_cert_payload_json(state.device_certificate_json, payload)) return;

  JsonVariant consumers = payload["authorized_consumers"];
  if (!consumers.is<JsonArray>()) return;
  for (JsonVariant v : consumers.as<JsonArray>()) {
    String c = String((const char*)(v | ""));
    if (c == "auto-record") out_auto_record = true;
    if (c == "auto-decode") out_auto_decode = true;
  }
}

size_t parse_authorized_listener_ips_csv(const String& csv, IPAddress* out, size_t max_out) {
  if (max_out == 0 || out == nullptr) return 0;

  size_t n = 0;
  int start = 0;
  while (start <= csv.length() && n < max_out) {
    int comma = csv.indexOf(',', start);
    String ip_str = (comma < 0) ? csv.substring(start) : csv.substring(start, comma);
    ip_str.trim();

    if (ip_str.length() > 0) {
      IPAddress ip;
      if (ip.fromString(ip_str)) {
        out[n++] = ip;
      }
    }

    if (comma < 0) break;
    start = comma + 1;
  }

  return n;
}

String build_discovery_announcement_json(const AppState& state, uint16_t http_port) {
  JsonDocument d;
  d["discovery_version"] = 1;
  d["device_type"] = "audio-zero-trust-microphone";
  d["device_key_fingerprint_hex"] = state.device_sign_fingerprint_hex;
  const bool certified = state.device_certificate_serial.length() > 0;
  d["admin_key_fingerprint_hex"] = certified ? state.admin_fingerprint_hex : "";
  d["listener_key_fingerprint_hex"] = state.listener_fingerprint_hex;
  d["recorder_auth_fingerprint_hex"] = state.recorder_auth_fingerprint_hex;
  bool auto_record = false;
  bool auto_decode = false;
  extract_discovery_cert_flags(state, auto_record, auto_decode);
  d["cert_auto_record"] = auto_record;
  d["cert_auto_decode"] = auto_decode;
  d["device_name"] = state.device_label;
  d["http_port"] = http_port;
  d["certificate_serial"] = certified ? state.device_certificate_serial : "";

  String out;
  serializeJson(d, out);
  return out;
}

void maybe_broadcast_discovery_announcement(const AppState& state) {
  static uint32_t last_ms = 0;
  static WiFiUDP udp;
  static bool udp_started = false;

  if (WiFi.status() != WL_CONNECTED) return;
  if (state.discovery_announcement_json.length() == 0) return;

  // Gate discovery until stream/TLS are fully ready to avoid premature recorder dial attempts.
  const bool stream_ready = state.signed_config_ready &&
                            state.admin_pubkey_pem.length() > 0 && state.admin_fingerprint_hex.length() == 64 &&
                            state.listener_pubkey_pem.length() > 0 && state.listener_fingerprint_hex.length() == 64;
  const bool tls_ready = state.tls_server_cert_configured && state.tls_server_key_configured;
  if (!stream_ready || !tls_ready) return;

  uint32_t now = millis();
  if ((now - last_ms) < 10000UL) return;
  last_ms = now;

  if (!udp_started) {
    udp.begin(0);
    udp_started = true;
  }

  bool sent_unicast = false;
  IPAddress targets[8];
  size_t target_count = parse_authorized_listener_ips_csv(state.authorized_listener_ips_csv, targets, 8);
  for (size_t i = 0; i < target_count; ++i) {
    udp.beginPacket(targets[i], kDiscoveryPort);
    udp.write(reinterpret_cast<const uint8_t*>(state.discovery_announcement_json.c_str()),
              state.discovery_announcement_json.length());
    udp.endPacket();
    sent_unicast = true;
  }

  // Backward-compatible fallback: if no authorized listeners are configured,
  // continue LAN broadcast discovery.
  if (!sent_unicast) {
    IPAddress bcast(255, 255, 255, 255);
    udp.beginPacket(bcast, kDiscoveryPort);
    udp.write(reinterpret_cast<const uint8_t*>(state.discovery_announcement_json.c_str()),
              state.discovery_announcement_json.length());
    udp.endPacket();
  }
}

}  // namespace azt
