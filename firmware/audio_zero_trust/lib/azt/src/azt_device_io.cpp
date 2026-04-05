#include "azt_device_io.h"

#include <Arduino.h>
#include <WiFi.h>
#include <Wire.h>
#include <time.h>
#include <esp_sntp.h>
#include <ESPmDNS.h>

#include "azt_constants.h"

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

static bool i2c_ping_addr(uint8_t addr) {
  Wire.beginTransmission(addr);
  return Wire.endTransmission() == 0;
}

static bool i2c_write_reg(uint8_t addr, uint8_t reg, uint8_t val) {
  Wire.beginTransmission(addr);
  Wire.write(reg);
  Wire.write(val);
  return Wire.endTransmission() == 0;
}

static void setup_i2s_echo_base_std() {
  i2s_config_t cfg{};
  cfg.mode = (i2s_mode_t)(I2S_MODE_MASTER | I2S_MODE_RX);
  cfg.sample_rate = constants::audio::kDefaultSampleRateHz;
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
  pins.bck_io_num = static_cast<gpio_num_t>(constants::pins::kEchoBaseI2sBck);
  pins.ws_io_num = static_cast<gpio_num_t>(constants::pins::kEchoBaseI2sWs);
  pins.data_out_num = static_cast<gpio_num_t>(constants::pins::kEchoBaseI2sDataOut);
  pins.data_in_num = static_cast<gpio_num_t>(constants::pins::kEchoBaseI2sDataIn);

  i2s_driver_install(kI2SPort, &cfg, 0, nullptr);
  i2s_set_pin(kI2SPort, &pins);
  i2s_zero_dma_buffer(kI2SPort);
  i2s_start(kI2SPort);
}

static void setup_i2s_internal_pdm() {
  i2s_config_t cfg{};
  cfg.mode = (i2s_mode_t)(I2S_MODE_MASTER | I2S_MODE_RX | I2S_MODE_PDM);
  cfg.sample_rate = constants::audio::kDefaultSampleRateHz;
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
  pins.bck_io_num = static_cast<gpio_num_t>(constants::pins::kEchoBaseI2sWs);
  pins.ws_io_num = static_cast<gpio_num_t>(constants::pins::kEchoBaseI2sBck);
  pins.data_out_num = I2S_PIN_NO_CHANGE;
  pins.data_in_num = static_cast<gpio_num_t>(constants::pins::kEchoBaseI2sDataIn);

  i2s_driver_install(kI2SPort, &cfg, 0, nullptr);
  i2s_set_pin(kI2SPort, &pins);
  i2s_zero_dma_buffer(kI2SPort);
}

static void es8311_init_for_echo_base(const AppState& state) {
  const uint8_t a = constants::audio::kEs8311I2cAddress;
  i2c_write_reg(a, 0x00, 0x1F);
  delay(constants::audio::kCodecResetDelayMs);
  i2c_write_reg(a, 0x00, 0x00);
  i2c_write_reg(a, 0x00, 0x80);
  i2c_write_reg(a, 0x01, 0xBF);
  i2c_write_reg(a, 0x02, 0x10);
  i2c_write_reg(a, 0x03, 0x10);
  i2c_write_reg(a, 0x04, 0x10);
  i2c_write_reg(a, 0x05, 0x00);
  i2c_write_reg(a, 0x06, 0x03);
  i2c_write_reg(a, 0x07, 0x00);
  i2c_write_reg(a, 0x08, 0xFF);
  i2c_write_reg(a, 0x09, 0x10);
  i2c_write_reg(a, 0x0A, 0x10);
  i2c_write_reg(a, 0x14, 0x1A);
  i2c_write_reg(a, constants::audio::kEs8311RegPreampGain, state.audio_preamp_gain);
  i2c_write_reg(a, constants::audio::kEs8311RegAdcGain, state.audio_adc_gain);
  i2c_write_reg(a, 0x0D, 0x01);
  i2c_write_reg(a, 0x0E, 0x02);
  i2c_write_reg(a, 0x12, 0x00);
  i2c_write_reg(a, 0x13, 0x10);
  i2c_write_reg(a, 0x1C, 0x6A);
  i2c_write_reg(a, 0x37, 0x08);
}

void setup_audio_input(AppState& state) {
  // Probe Echo Base (ES8311 on Atom host I2C pins).
  Wire.begin(constants::pins::kEchoBaseI2cSda, constants::pins::kEchoBaseI2cScl, constants::audio::kEchoBaseI2cClockHz);
  delay(constants::audio::kEchoBaseProbeDelayMs);
  const bool has_echo = i2c_ping_addr(constants::audio::kEs8311I2cAddress);
  state.audio_echo_base_detected = has_echo;

  if (has_echo) {
    es8311_init_for_echo_base(state);
    setup_i2s_echo_base_std();
    state.audio_input_source = "echo_base";
    state.audio_sample_rate_hz = constants::audio::kDefaultSampleRateHz;
    state.audio_channels = constants::audio::kDefaultChannels;
    state.audio_sample_width_bytes = constants::audio::kDefaultSampleWidthBytes;
    Serial.printf("AZT_AUDIO source=echo_base preamp=%u adc=%u rate=%lu ch=%u sw=%u\n", state.audio_preamp_gain, state.audio_adc_gain, static_cast<unsigned long>(state.audio_sample_rate_hz), static_cast<unsigned>(state.audio_channels), static_cast<unsigned>(state.audio_sample_width_bytes));
    return;
  }

#if CONFIG_IDF_TARGET_ESP32S3
  // Atom EchoS3R has no internal fallback microphone path.
  state.audio_input_source = "none";
  state.audio_sample_rate_hz = 0;
  state.audio_channels = 0;
  state.audio_sample_width_bytes = 0;
  Serial.printf("AZT_AUDIO source=none reason=no_codec_detected\n");
#else
  setup_i2s_internal_pdm();
  state.audio_input_source = "internal_pdm";
  state.audio_sample_rate_hz = constants::audio::kDefaultSampleRateHz;
  state.audio_channels = constants::audio::kDefaultChannels;
  state.audio_sample_width_bytes = constants::audio::kDefaultSampleWidthBytes;
  Serial.printf("AZT_AUDIO source=internal_pdm rate=%lu ch=%u sw=%u\n", static_cast<unsigned long>(state.audio_sample_rate_hz), static_cast<unsigned>(state.audio_channels), static_cast<unsigned>(state.audio_sample_width_bytes));
#endif
}

void setup_i2s_pdm_mic() {
  // Backward-compatible wrapper.
  setup_i2s_internal_pdm();
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
    MDNS.addService("https", "tcp", constants::runtime::kApiTlsPort);
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

static bool setup_wifi_ap_mode(AppState& state, const char* src, const String& ap_ssid_in, const String& ap_pass_in) {
  String ap_ssid = ap_ssid_in;
  String ap_pass = ap_pass_in;
  if (ap_ssid.length() == 0) {
    String suffix = state.device_chip_id_hex;
    suffix.replace(":", "");
    suffix.toLowerCase();
    String ssid_suffix = suffix.length() >= 6 ? suffix.substring(suffix.length() - 6) : suffix;
    if (ssid_suffix.length() == 0) ssid_suffix = "device";
    ap_ssid = String("azt-mic-") + ssid_suffix;
  }
  if (ap_pass.length() < 8) {
    String suffix = state.device_chip_id_hex;
    suffix.replace(":", "");
    suffix.toLowerCase();
    String pass_suffix = suffix.length() >= 8 ? suffix.substring(suffix.length() - 8) : suffix;
    while (pass_suffix.length() < 8) pass_suffix += "0";
    ap_pass = String("azt") + pass_suffix;
  }

  WiFi.mode(WIFI_AP);
  delay(100);
  IPAddress ap_ip(10, 0, 0, 1);
  IPAddress ap_gw(10, 0, 0, 1);
  IPAddress ap_mask(255, 255, 255, 0);
  const bool ap_cfg_ok = WiFi.softAPConfig(ap_ip, ap_gw, ap_mask);
  if (!ap_cfg_ok) Serial.printf("AZT_WIFI_AP_CFG_FAIL src=%s\n", src);

  if (WiFi.softAP(ap_ssid.c_str(), ap_pass.c_str())) {
    IPAddress ip = WiFi.softAPIP();
    state.wifi_ap_ssid = ap_ssid;
    state.wifi_ap_pass = ap_pass;
    state.wifi_last_connect_source = String(src);
    state.wifi_last_status = static_cast<int>(WL_CONNECTED);
    Serial.printf("AZT_WIFI_AP_OK src=%s ssid=%s ip=%u.%u.%u.%u\n", src, ap_ssid.c_str(), ip[0], ip[1], ip[2], ip[3]);
    return true;
  }
  state.wifi_last_connect_source = String(src);
  state.wifi_last_status = static_cast<int>(WL_CONNECT_FAILED);
  Serial.printf("AZT_WIFI_AP_FAIL src=%s ssid=%s\n", src, ap_ssid.c_str());
  return false;
}

void setup_wifi(AppState& state) {
  WiFi.persistent(false);

  if (state.wifi_mode == "ap") {
    (void)setup_wifi_ap_mode(state, "state-ap", state.wifi_ap_ssid, state.wifi_ap_pass);
    maybe_maintain_mdns(state);
    return;
  }

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
  if (state.wifi_mode == "ap") {
    maybe_maintain_mdns(state);
    return;
  }
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
