#include "test_azt_registry.h"

#include "azt_discovery.h"

namespace azt_test {
namespace {

bool test_discovery_payload_precise(Context&) {
  azt::AppState st{};
  st.device_sign_fingerprint_hex = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
  st.admin_fingerprint_hex = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
  st.listener_fingerprint_hex = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
  st.device_label = "Livingroom";
  st.device_certificate_serial = "mic-000001";

  String got = azt::build_discovery_announcement_json(st, 8080);
  String expected = "{\"discovery_version\":1,\"device_type\":\"audio-zero-trust-microphone\",\"device_key_fingerprint_hex\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"admin_key_fingerprint_hex\":\"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\",\"listener_key_fingerprint_hex\":\"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc\",\"device_name\":\"Livingroom\",\"http_port\":8080,\"certificate_serial\":\"mic-000001\"}";
  return got == expected;
}

bool test_discovery_payload_uncertified_blanks_admin(Context&) {
  azt::AppState st{};
  st.device_sign_fingerprint_hex = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
  st.admin_fingerprint_hex = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
  st.listener_fingerprint_hex = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
  st.device_label = "Livingroom";
  st.device_certificate_serial = "";

  String got = azt::build_discovery_announcement_json(st, 8080);
  String expected = "{\"discovery_version\":1,\"device_type\":\"audio-zero-trust-microphone\",\"device_key_fingerprint_hex\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"admin_key_fingerprint_hex\":\"\",\"listener_key_fingerprint_hex\":\"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc\",\"device_name\":\"Livingroom\",\"http_port\":8080,\"certificate_serial\":\"\"}";
  return got == expected;
}

bool test_parse_authorized_listener_ips_csv(Context&) {
  IPAddress out[8];
  size_t n = azt::parse_authorized_listener_ips_csv("192.168.1.10, 192.168.1.20,10.0.0.2", out, 8);
  if (n != 3) return false;
  return out[0].toString() == "192.168.1.10" &&
         out[1].toString() == "192.168.1.20" &&
         out[2].toString() == "10.0.0.2";
}

bool test_parse_authorized_listener_ips_csv_skips_invalid(Context&) {
  IPAddress out[8];
  size_t n = azt::parse_authorized_listener_ips_csv("foo, 192.168.1.10, , 300.1.1.1,10.0.0.9", out, 8);
  if (n != 2) return false;
  return out[0].toString() == "192.168.1.10" && out[1].toString() == "10.0.0.9";
}

bool test_parse_authorized_listener_ips_csv_respects_capacity(Context&) {
  IPAddress out[1];
  size_t n = azt::parse_authorized_listener_ips_csv("192.168.1.10,192.168.1.11", out, 1);
  return n == 1 && out[0].toString() == "192.168.1.10";
}

bool test_parse_authorized_listener_ips_csv_empty(Context&) {
  IPAddress out[4];
  size_t n = azt::parse_authorized_listener_ips_csv("", out, 4);
  return n == 0;
}

bool test_parse_authorized_listener_ips_csv_whitespace_and_commas(Context&) {
  IPAddress out[8];
  size_t n = azt::parse_authorized_listener_ips_csv(" , 192.168.1.10 , ,10.0.0.7, ", out, 8);
  return n == 2 && out[0].toString() == "192.168.1.10" && out[1].toString() == "10.0.0.7";
}

bool test_parse_authorized_listener_ips_csv_zero_capacity(Context&) {
  IPAddress out[1];
  size_t n = azt::parse_authorized_listener_ips_csv("192.168.1.10", out, 0);
  return n == 0;
}

}  // namespace

void register_test_azt_discovery(Registry& out) {
  out.push_back({"DISCOVERY_PAYLOAD_PRECISE", test_discovery_payload_precise, "discovery payload format mismatch"});
  out.push_back({"DISCOVERY_PAYLOAD_UNCERTIFIED_BLANKS_ADMIN", test_discovery_payload_uncertified_blanks_admin, "uncertified discovery should blank admin/cert fields"});
  out.push_back({"PARSE_AUTH_LISTENER_IPS_CSV", test_parse_authorized_listener_ips_csv, "authorized listener IP CSV parse mismatch"});
  out.push_back({"PARSE_AUTH_LISTENER_IPS_CSV_SKIPS_INVALID", test_parse_authorized_listener_ips_csv_skips_invalid, "authorized listener parser should skip invalid entries"});
  out.push_back({"PARSE_AUTH_LISTENER_IPS_CSV_RESPECTS_CAPACITY", test_parse_authorized_listener_ips_csv_respects_capacity, "authorized listener parser should respect output capacity"});
  out.push_back({"PARSE_AUTH_LISTENER_IPS_CSV_EMPTY", test_parse_authorized_listener_ips_csv_empty, "authorized listener parser should handle empty csv"});
  out.push_back({"PARSE_AUTH_LISTENER_IPS_CSV_WHITESPACE_AND_COMMAS", test_parse_authorized_listener_ips_csv_whitespace_and_commas, "authorized listener parser should ignore empty/whitespace csv entries"});
  out.push_back({"PARSE_AUTH_LISTENER_IPS_CSV_ZERO_CAPACITY", test_parse_authorized_listener_ips_csv_zero_capacity, "authorized listener parser should handle zero capacity"});
}

}  // namespace azt_test
