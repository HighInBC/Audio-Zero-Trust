#pragma once

#include <driver/i2s.h>

#include "azt_app_state.h"

namespace azt {

constexpr i2s_port_t kI2SPort = I2S_NUM_0;

enum class WifiMaintainDecision {
  kSkipInterval,
  kSkipNoCreds,
  kSkipAlreadyConnected,
  kReconnectStateChange,
  kReconnectStateRetry,
};

void setup_i2s_pdm_mic();
void setup_audio_input(AppState& state);
// Reapply active audio input gain/config registers at runtime (best-effort).
void reapply_audio_input_registers(const AppState& state);

// Testable helpers.
bool has_wifi_credentials(const AppState& state);
bool is_wifi_connected_status(int wifi_status);
void record_wifi_connect_result(AppState& state, const char* src, int wifi_status);
WifiMaintainDecision decide_wifi_maintain(const AppState& state,
                                          const String& last_ssid,
                                          const String& last_pass,
                                          int wifi_status,
                                          uint32_t now_ms,
                                          uint32_t last_check_ms,
                                          uint32_t min_interval_ms = 5000UL);

struct WifiMaintainPlan {
  WifiMaintainDecision decision = WifiMaintainDecision::kSkipInterval;
  bool should_update_cache = false;
  bool should_connect = false;
  const char* connect_source = "state-reconnect";
};
WifiMaintainPlan make_wifi_maintain_plan(WifiMaintainDecision decision);
void update_wifi_maintain_cache(const AppState& state,
                                uint32_t now_ms,
                                uint32_t& inout_last_check_ms,
                                String& inout_last_ssid,
                                String& inout_last_pass);

bool should_attempt_wifi_connect(WifiMaintainDecision decision);
const char* wifi_connect_source_for_decision(WifiMaintainDecision decision);
bool should_emit_wifi_timeout_log(bool connected);

enum class WifiSetupResult {
  kNotConfigured,
  kConnected,
  kTimeout,
};
WifiSetupResult evaluate_setup_wifi_result(bool has_creds, bool connected);
bool should_attempt_setup_wifi_connect(bool has_creds);
int extract_time_servers_csv(const String& csv, String out_servers[3]);
bool should_skip_time_sync(int wifi_status, const String& time_servers_csv);

enum class SntpStartAction {
  kInit,
  kRestart,
};
SntpStartAction choose_sntp_start_action(bool already_enabled);

void setup_wifi(AppState& state);
void maybe_maintain_wifi(AppState& state);
void setup_time_sync(AppState& state);
void maybe_refresh_time_sync(AppState& state);

}  // namespace azt
