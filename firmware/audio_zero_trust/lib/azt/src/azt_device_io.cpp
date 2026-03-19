#include "azt_device_io.h"

#include <Arduino.h>
#include <WiFi.h>
#include <time.h>
#include <esp_sntp.h>
#include <ESPmDNS.h>

namespace azt {

bool has_wifi_credentials(const AppState& state) {
  return state.wifi_ssid.length() > 0 && state.wifi_pass.length() > 0;
}

bool is_wifi_connected_status(int wifi_status) {
  return wifi_status == WL_CONNECTED;
}

void record_wifi_connect_result(AppState& state, const char* src, int wifi_status) {
  state.wifi_last_connect_source = String(src ? src : "");
  state.wifi_last_status = wifi_status;
}

WifiMaintainDecision decide_wifi_maintain(const AppState& state,
                                          const String& last_ssid,
                                          const String& last_pass,
                                          int wifi_status,
                                          uint32_t now_ms,
                                          uint32_t last_check_ms,
                                          uint32_t min_interval_ms) {
  const bool creds_changed = (state.wifi_ssid != last_ssid) || (state.wifi_pass != last_pass);
  if (!creds_changed && (now_ms - last_check_ms) < min_interval_ms) return WifiMaintainDecision::kSkipInterval;
  if (!has_wifi_credentials(state)) return WifiMaintainDecision::kSkipNoCreds;
  if (is_wifi_connected_status(wifi_status) && !creds_changed) return WifiMaintainDecision::kSkipAlreadyConnected;
  return creds_changed ? WifiMaintainDecision::kReconnectStateChange : WifiMaintainDecision::kReconnectStateRetry;
}

bool should_attempt_wifi_connect(WifiMaintainDecision decision) {
  return decision == WifiMaintainDecision::kReconnectStateChange ||
         decision == WifiMaintainDecision::kReconnectStateRetry;
}

const char* wifi_connect_source_for_decision(WifiMaintainDecision decision) {
  return decision == WifiMaintainDecision::kReconnectStateChange ? "state-change" : "state-reconnect";
}

WifiMaintainPlan make_wifi_maintain_plan(WifiMaintainDecision decision) {
  WifiMaintainPlan p{};
  p.decision = decision;
  p.should_update_cache = decision != WifiMaintainDecision::kSkipInterval;
  p.should_connect = should_attempt_wifi_connect(decision);
  p.connect_source = wifi_connect_source_for_decision(decision);
  return p;
}

void update_wifi_maintain_cache(const AppState& state,
                                uint32_t now_ms,
                                uint32_t& inout_last_check_ms,
                                String& inout_last_ssid,
                                String& inout_last_pass) {
  inout_last_check_ms = now_ms;
  inout_last_ssid = state.wifi_ssid;
  inout_last_pass = state.wifi_pass;
}

bool should_emit_wifi_timeout_log(bool connected) {
  return !connected;
}

WifiSetupResult evaluate_setup_wifi_result(bool has_creds, bool connected) {
  if (!has_creds) return WifiSetupResult::kNotConfigured;
  return connected ? WifiSetupResult::kConnected : WifiSetupResult::kTimeout;
}

bool should_attempt_setup_wifi_connect(bool has_creds) {
  return has_creds;
}

int extract_time_servers_csv(const String& csv, String out_servers[3]) {
  int idx = 0;
  int start = 0;
  while (idx < 3 && start <= csv.length()) {
    int comma = csv.indexOf(',', start);
    String token = (comma < 0) ? csv.substring(start) : csv.substring(start, comma);
    token.trim();
    if (token.length() > 0) out_servers[idx++] = token;
    if (comma < 0) break;
    start = comma + 1;
  }
  return idx;
}

bool should_skip_time_sync(int wifi_status, const String& time_servers_csv) {
  return wifi_status != WL_CONNECTED || time_servers_csv.length() == 0;
}

SntpStartAction choose_sntp_start_action(bool already_enabled) {
  return already_enabled ? SntpStartAction::kRestart : SntpStartAction::kInit;
}

void setup_i2s_pdm_mic() {
  i2s_config_t cfg{};
  cfg.mode = (i2s_mode_t)(I2S_MODE_MASTER | I2S_MODE_RX | I2S_MODE_PDM);
  cfg.sample_rate = 16000;
  cfg.bits_per_sample = I2S_BITS_PER_SAMPLE_16BIT;
  cfg.channel_format = I2S_CHANNEL_FMT_ONLY_RIGHT;
  cfg.communication_format = I2S_COMM_FORMAT_STAND_I2S;
  cfg.intr_alloc_flags = ESP_INTR_FLAG_LEVEL1;
  cfg.dma_buf_count = 8;
  cfg.dma_buf_len = 256;
  cfg.use_apll = false;
  cfg.tx_desc_auto_clear = false;
  cfg.fixed_mclk = 0;

  i2s_pin_config_t pins{};
  pins.bck_io_num = GPIO_NUM_19;
  pins.ws_io_num = GPIO_NUM_33;
  pins.data_out_num = I2S_PIN_NO_CHANGE;
  pins.data_in_num = GPIO_NUM_23;

  i2s_driver_install(kI2SPort, &cfg, 0, nullptr);
  i2s_set_pin(kI2SPort, &pins);
  i2s_zero_dma_buffer(kI2SPort);
}

static String sanitize_mdns_hostname(const String& in) {
  String out;
  out.reserve(in.length());
  for (size_t i = 0; i < in.length(); ++i) {
    char c = in[i];
    if ((c >= 'A' && c <= 'Z')) c = static_cast<char>(c - 'A' + 'a');
    bool ok = (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-';
    out += ok ? c : '-';
  }
  while (out.startsWith("-")) out.remove(0, 1);
  while (out.endsWith("-")) out.remove(out.length() - 1, 1);
  if (out.length() > 63) out = out.substring(0, 63);
  return out;
}

static void maybe_maintain_mdns(AppState& state) {
  static bool mdns_started = false;
  static String last_host;

  if (WiFi.status() != WL_CONNECTED || !state.mdns_enabled) {
    if (mdns_started) {
      MDNS.end();
      mdns_started = false;
      last_host = "";
    }
    return;
  }

  String desired = sanitize_mdns_hostname(state.mdns_hostname);
  if (desired.length() == 0) {
    desired = sanitize_mdns_hostname(state.device_label);
  }
  if (desired.length() == 0) desired = String("azt-device");

  if (mdns_started && desired == last_host) return;
  if (mdns_started) {
    MDNS.end();
    mdns_started = false;
    last_host = "";
  }

  if (MDNS.begin(desired.c_str())) {
    mdns_started = true;
    last_host = desired;
    state.mdns_hostname = desired;
    MDNS.addService("http", "tcp", 8080);
    Serial.printf("AZT_MDNS_OK host=%s.local\n", desired.c_str());
  } else {
    Serial.printf("AZT_MDNS_FAIL host=%s\n", desired.c_str());
  }
}

static bool connect_wifi_with_state(AppState& state, const char* src, const char* ssid, const char* pass, uint32_t timeout_ms) {
  WiFi.disconnect(true, true);
  delay(150);
  Serial.printf("AZT_WIFI_CONNECT src=%s ssid=%s pass_len=%u\n",
                src,
                ssid ? ssid : "",
                static_cast<unsigned>(pass ? strlen(pass) : 0));
  WiFi.begin(ssid, pass);
  uint32_t start = millis();
  while (WiFi.status() != WL_CONNECTED && (millis() - start) < timeout_ms) delay(200);
  int final_status = static_cast<int>(WiFi.status());
  if (is_wifi_connected_status(final_status)) {
    IPAddress ip = WiFi.localIP();
    record_wifi_connect_result(state, src, final_status);
    Serial.printf("AZT_WIFI_CONNECTED src=%s ip=%u.%u.%u.%u\n", src, ip[0], ip[1], ip[2], ip[3]);
    return true;
  }
  record_wifi_connect_result(state, src, final_status);
  Serial.printf("AZT_WIFI_CONNECT_FAIL src=%s status=%d\n", src, final_status);
  return false;
}

void setup_wifi(AppState& state) {
  WiFi.persistent(false);
  WiFi.mode(WIFI_STA);

  bool has_creds = has_wifi_credentials(state);
  bool connected = false;

  if (should_attempt_setup_wifi_connect(has_creds)) {
    connected = connect_wifi_with_state(state, "state", state.wifi_ssid.c_str(), state.wifi_pass.c_str(), 10000);
  }

  maybe_maintain_mdns(state);

  switch (evaluate_setup_wifi_result(has_creds, connected)) {
    case WifiSetupResult::kNotConfigured:
      Serial.printf("AZT_WIFI_NOT_CONFIGURED\n");
      break;
    case WifiSetupResult::kConnected: {
      IPAddress ip = WiFi.localIP();
      Serial.printf("AZT_IP=%u.%u.%u.%u\n", ip[0], ip[1], ip[2], ip[3]);
      break;
    }
    case WifiSetupResult::kTimeout:
      if (should_emit_wifi_timeout_log(connected)) {
        Serial.printf("AZT_WIFI_TIMEOUT status=%d\n", static_cast<int>(WiFi.status()));
      }
      break;
  }
}

void maybe_maintain_wifi(AppState& state) {
  static uint32_t last_check_ms = 0;
  static String last_ssid;
  static String last_pass;

  const uint32_t now = millis();
  WifiMaintainDecision d = decide_wifi_maintain(state,
                                                last_ssid,
                                                last_pass,
                                                static_cast<int>(WiFi.status()),
                                                now,
                                                last_check_ms,
                                                5000UL);
  WifiMaintainPlan plan = make_wifi_maintain_plan(d);

  if (!plan.should_update_cache) return;

  update_wifi_maintain_cache(state, now, last_check_ms, last_ssid, last_pass);

  if (plan.should_connect) {
    (void)connect_wifi_with_state(state,
                                  plan.connect_source,
                                  state.wifi_ssid.c_str(),
                                  state.wifi_pass.c_str(),
                                  8000);
  }

  maybe_maintain_mdns(state);
}

static AppState* g_time_state = nullptr;
static portMUX_TYPE g_time_mux = portMUX_INITIALIZER_UNLOCKED;

static void on_sntp_time_sync(struct timeval* tv) {
  if (!tv || !g_time_state) return;
  const uint32_t epoch = static_cast<uint32_t>(tv->tv_sec);
  if (epoch < 1700000000) return;

  portENTER_CRITICAL(&g_time_mux);
  g_time_state->time_synced = true;
  g_time_state->time_last_sync_epoch = epoch;
  g_time_state->time_last_sync_millis = millis();
  portEXIT_CRITICAL(&g_time_mux);

  Serial.printf("AZT_TIME_SYNC_OK epoch=%u\n", static_cast<unsigned>(epoch));
}

void setup_time_sync(AppState& state) {
  g_time_state = &state;

  if (should_skip_time_sync(static_cast<int>(WiFi.status()), state.time_servers_csv)) {
    if (WiFi.status() != WL_CONNECTED) {
      Serial.printf("AZT_TIME_SYNC_SKIP wifi_down\n");
    } else {
      Serial.printf("AZT_TIME_SYNC_SKIP no_servers\n");
    }
    return;
  }

  sntp_setoperatingmode(SNTP_OPMODE_POLL);

  String servers[3];
  int idx = extract_time_servers_csv(state.time_servers_csv, servers);
  for (int i = 0; i < idx; ++i) {
    const String& token = servers[i];
    char* srv = static_cast<char*>(malloc(token.length() + 1));
    if (srv) {
      memcpy(srv, token.c_str(), token.length() + 1);
      sntp_setservername(i, srv);
    }
  }

  if (idx == 0) {
    Serial.printf("AZT_TIME_SYNC_SKIP invalid_servers\n");
    return;
  }

  sntp_set_sync_interval(600000);  // 10 minutes
  sntp_set_time_sync_notification_cb(on_sntp_time_sync);

  if (choose_sntp_start_action(sntp_enabled()) == SntpStartAction::kRestart) {
    sntp_restart();
  } else {
    sntp_init();
  }

  Serial.printf("AZT_TIME_SYNC_INIT servers=%d interval_s=%u\n", idx, static_cast<unsigned>(sntp_get_sync_interval() / 1000));
}

void maybe_refresh_time_sync(AppState& state) {
  (void)state;
  // SNTP polling is callback-driven and periodic once initialized.
}

}  // namespace azt
