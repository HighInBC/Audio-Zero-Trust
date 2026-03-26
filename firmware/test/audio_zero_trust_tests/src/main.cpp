#include <Arduino.h>
#include <ArduinoJson.h>
#include <mbedtls/base64.h>
#include <esp_system.h>

#include <vector>

#include "azt_crypto.h"
#include "test_azt_registry.h"
#include "test_azt_crypto.h"
#include "test_azt_stream.h"
#include "test_azt_discovery.h"
#include "test_azt_http_api.h"
#include "test_azt_config.h"

namespace {

String g_pubkey_pem;
azt_test::Registry g_registry;
azt_test::Context g_ctx;

bool g_test_pending = false;
uint32_t g_pending_id = 0;
uint8_t g_expected_plain[32] = {0};
String g_pending_test_name;
String g_pending_scenario = "normal";
uint32_t g_pending_started_ms = 0;

bool g_suite_running = false;
uint32_t g_suite_total = 0;
uint32_t g_suite_pass = 0;
uint32_t g_suite_fail = 0;
int g_async_suite_index = -1;

String json_line(const JsonDocument& doc) {
  String out;
  serializeJson(doc, out);
  return out;
}

void emit_status(const char* level, const char* msg) {
  JsonDocument d;
  d["event"] = "STATUS";
  d["level"] = level;
  d["msg"] = msg;
  Serial.println(json_line(d));
}

void emit_test_result(const char* name, bool ok, const char* detail = nullptr) {
  JsonDocument d;
  d["event"] = "TEST_RESULT";
  d["name"] = name;
  d["ok"] = ok;
  if (!ok && detail && detail[0]) d["detail"] = detail;
  Serial.println(json_line(d));

  if (g_suite_running) {
    if (ok) g_suite_pass++;
    else g_suite_fail++;
  }
}

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

void run_test_by_name(const String& name);

void maybe_run_next_async_suite_test() {
  if (!g_suite_running || g_test_pending) return;
  static const char* kAsyncTests[] = {
      "RSA_WRAP_AES_ROUNDTRIP",
      "RSA_WRAP_AES_EXPECT_BAD_ID",
      "RSA_WRAP_AES_EXPECT_BAD_B64",
      "RSA_WRAP_AES_EXPECT_BAD_PLAIN",
      "RSA_WRAP_AES_EXPECT_TIMEOUT",
      "RSA_WRAP_AES_EXPECT_DUPLICATE",
  };
  if (g_async_suite_index < 0) return;
  if (g_async_suite_index >= static_cast<int>(sizeof(kAsyncTests) / sizeof(kAsyncTests[0]))) return;

  const char* next_name = kAsyncTests[g_async_suite_index++];
  run_test_by_name(String(next_name));
}

void maybe_finish_suite() {
  if (!g_suite_running) return;
  if (g_test_pending) return;
  if ((g_suite_pass + g_suite_fail) < g_suite_total) return;

  JsonDocument d;
  d["event"] = "TEST_SUMMARY";
  d["total"] = g_suite_total;
  d["pass"] = g_suite_pass;
  d["fail"] = g_suite_fail;
  d["ok"] = (g_suite_fail == 0);
  Serial.println(json_line(d));

  g_suite_running = false;
  g_async_suite_index = -1;
}

void start_rsa_wrap_test(const char* test_name, const char* scenario) {
  if (g_pubkey_pem.length() < 64) {
    emit_test_result(test_name, false, "no pubkey installed");
    maybe_finish_suite();
    return;
  }

  esp_fill_random(g_expected_plain, sizeof(g_expected_plain));
  std::vector<uint8_t> wrapped;
  std::vector<uint8_t> pub(reinterpret_cast<const uint8_t*>(g_pubkey_pem.c_str()),
                           reinterpret_cast<const uint8_t*>(g_pubkey_pem.c_str()) + g_pubkey_pem.length() + 1);

  if (!azt::rsa_oaep_sha256_encrypt_pub(pub.data(), pub.size(), g_expected_plain, sizeof(g_expected_plain), wrapped)) {
    emit_test_result(test_name, false, "rsa wrap failed");
    maybe_finish_suite();
    return;
  }

  g_test_pending = true;
  g_pending_test_name = String(test_name);
  g_pending_scenario = String(scenario ? scenario : "normal");
  g_pending_started_ms = millis();
  g_pending_id++;

  JsonDocument d;
  d["event"] = "RSA_WRAP_AES_REQ";
  d["id"] = g_pending_id;
  d["wrapped_b64"] = azt::b64(wrapped.data(), wrapped.size());
  d["scenario"] = g_pending_scenario;
  Serial.println(json_line(d));
}

void handle_rsa_resp(JsonDocument& in) {
  if (!g_test_pending) {
    emit_status("error", "unexpected RSA response; no test pending");
    return;
  }

  uint32_t id = in["id"] | 0;
  const bool expect_bad_id = (g_pending_scenario == "bad_id");
  const bool expect_bad_b64 = (g_pending_scenario == "bad_b64");
  const bool expect_bad_plain = (g_pending_scenario == "bad_plain");

  if (id != g_pending_id) {
    emit_test_result(g_pending_test_name.c_str(), expect_bad_id, expect_bad_id ? nullptr : "response id mismatch");
    g_test_pending = false;
    maybe_finish_suite();
    maybe_run_next_async_suite_test();
    return;
  }

  const char* plain_b64 = in["plain_b64"] | "";
  std::vector<uint8_t> plain;
  if (!b64_decode_to_vec(String(plain_b64), plain)) {
    emit_test_result(g_pending_test_name.c_str(), expect_bad_b64, expect_bad_b64 ? nullptr : "invalid plain_b64");
    g_test_pending = false;
    maybe_finish_suite();
    maybe_run_next_async_suite_test();
    return;
  }

  bool same_plain = (plain.size() == sizeof(g_expected_plain) &&
                     memcmp(plain.data(), g_expected_plain, sizeof(g_expected_plain)) == 0);

  if (expect_bad_plain) {
    emit_test_result(g_pending_test_name.c_str(), !same_plain, !same_plain ? nullptr : "expected plaintext mismatch not observed");
  } else {
    emit_test_result(g_pending_test_name.c_str(), same_plain, same_plain ? nullptr : "decrypted plaintext mismatch");
  }

  g_test_pending = false;
  maybe_finish_suite();
  maybe_run_next_async_suite_test();
}

void run_sync_test_by_name(const String& name) {
  for (const auto& tc : g_registry) {
    if (name == tc.name) {
      bool ok = tc.fn(g_ctx);
      emit_test_result(tc.name, ok, ok ? nullptr : tc.fail_detail);
      return;
    }
  }
}

void run_test_by_name(const String& name) {
  if (name == "RSA_WRAP_AES_ROUNDTRIP") return start_rsa_wrap_test("RSA_WRAP_AES_ROUNDTRIP", "normal");
  if (name == "RSA_WRAP_AES_EXPECT_BAD_ID") return start_rsa_wrap_test("RSA_WRAP_AES_EXPECT_BAD_ID", "bad_id");
  if (name == "RSA_WRAP_AES_EXPECT_BAD_B64") return start_rsa_wrap_test("RSA_WRAP_AES_EXPECT_BAD_B64", "bad_b64");
  if (name == "RSA_WRAP_AES_EXPECT_BAD_PLAIN") return start_rsa_wrap_test("RSA_WRAP_AES_EXPECT_BAD_PLAIN", "bad_plain");
  if (name == "RSA_WRAP_AES_EXPECT_TIMEOUT") return start_rsa_wrap_test("RSA_WRAP_AES_EXPECT_TIMEOUT", "no_response");
  if (name == "RSA_WRAP_AES_EXPECT_DUPLICATE") return start_rsa_wrap_test("RSA_WRAP_AES_EXPECT_DUPLICATE", "duplicate");

  run_sync_test_by_name(name);
}

void emit_test_list() {
  JsonDocument d;
  d["event"] = "TEST_LIST";
  JsonArray tests = d["tests"].to<JsonArray>();
  for (const auto& tc : g_registry) tests.add(tc.name);
  tests.add("RSA_WRAP_AES_ROUNDTRIP");
  tests.add("RSA_WRAP_AES_EXPECT_BAD_ID");
  tests.add("RSA_WRAP_AES_EXPECT_BAD_B64");
  tests.add("RSA_WRAP_AES_EXPECT_BAD_PLAIN");
  tests.add("RSA_WRAP_AES_EXPECT_TIMEOUT");
  tests.add("RSA_WRAP_AES_EXPECT_DUPLICATE");
  Serial.println(json_line(d));
}

void run_all_tests() {
  g_suite_running = true;
  g_suite_total = g_registry.size() + 6;
  g_suite_pass = 0;
  g_suite_fail = 0;

  for (const auto& tc : g_registry) run_test_by_name(tc.name);

  g_async_suite_index = 0;
  maybe_run_next_async_suite_test();
  maybe_finish_suite();
}

void check_pending_timeout() {
  if (!g_test_pending) return;
  if (millis() - g_pending_started_ms < 3000) return;

  const bool expect_timeout = (g_pending_scenario == "no_response");
  emit_test_result(g_pending_test_name.c_str(), expect_timeout,
                   expect_timeout ? nullptr : "async response timeout");
  g_test_pending = false;
  maybe_finish_suite();
  maybe_run_next_async_suite_test();
}

void handle_command_line(const String& line) {
  JsonDocument in;
  auto err = deserializeJson(in, line);
  if (err) {
    JsonDocument d;
    d["event"] = "STATUS";
    d["level"] = "error";
    d["msg"] = "invalid json command";
    d["json_error"] = err.c_str();
    d["line_len"] = line.length();
    String head = line.substring(0, 80);
    d["line_head"] = head;
    Serial.println(json_line(d));
    return;
  }

  String cmd = String((const char*)(in["cmd"] | ""));

  if (cmd == "PING") {
    JsonDocument d;
    d["event"] = "PONG";
    d["ok"] = true;
    Serial.println(json_line(d));
    return;
  }

  if (cmd == "TEST_LIST") {
    emit_test_list();
    return;
  }

  if (cmd == "PUBKEY_SET") {
    const char* pem_b64 = in["pem_b64"] | "";
    std::vector<uint8_t> pem;
    if (!b64_decode_to_vec(String(pem_b64), pem) || pem.empty()) {
      emit_status("error", "invalid pem_b64");
      return;
    }
    g_pubkey_pem = String(reinterpret_cast<const char*>(pem.data()));
    JsonDocument d;
    d["event"] = "PUBKEY_SET_OK";
    d["len"] = g_pubkey_pem.length();
    Serial.println(json_line(d));
    return;
  }

  if (cmd == "RUN_TEST") {
    String name = String((const char*)(in["name"] | ""));
    run_test_by_name(name);
    return;
  }

  if (cmd == "RUN_ALL") {
    run_all_tests();
    return;
  }

  if (cmd == "RSA_WRAP_AES_RESP") {
    handle_rsa_resp(in);
    return;
  }

  emit_status("error", "unknown cmd");
}

}  // namespace

void setup() {
  Serial.begin(115200);
  delay(200);

  g_ctx.pubkey_pem = &g_pubkey_pem;

  azt_test::register_test_azt_crypto(g_registry);
  azt_test::register_test_azt_stream(g_registry);
  azt_test::register_test_azt_discovery(g_registry);
  azt_test::register_test_azt_http_api(g_registry);
  azt_test::register_test_azt_config(g_registry);

  emit_status("info", "libtest firmware ready");
  emit_test_list();
}

void loop() {
  check_pending_timeout();

  if (!Serial.available()) {
    delay(5);
    return;
  }
  String line = Serial.readStringUntil('\n');
  line.trim();
  if (line.length() == 0) return;
  handle_command_line(line);
}
