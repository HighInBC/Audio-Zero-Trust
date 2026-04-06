#pragma once

#include <Arduino.h>
#include "azt_app_state.h"

namespace azt {

static constexpr uint16_t kHttpPort = 8080;

void load_config_state(AppState& state);
bool save_config_state(AppState& state,
                       const String& admin_pem,
                       const String& admin_fp,
                       const String& listener_pem,
                       const String& listener_fp,
                       const String& device_label,
                       const String& wifi_mode,
                       const String& wifi_ssid,
                       const String& wifi_pass,
                       const String& wifi_ap_ssid,
                       const String& wifi_ap_pass,
                       bool signed_ok,
                       const String& authorized_listener_ips_csv = "",
                       const String& time_servers_csv = "",
                       bool mdns_enabled = false,
                       const String& mdns_hostname = "");

bool save_config_state(AppState& state,
                       const String& admin_pem,
                       const String& admin_fp,
                       const String& device_label,
                       const String& wifi_mode,
                       const String& wifi_ssid,
                       const String& wifi_pass,
                       const String& wifi_ap_ssid,
                       const String& wifi_ap_pass,
                       bool signed_ok,
                       const String& authorized_listener_ips_csv = "",
                       const String& time_servers_csv = "",
                       bool mdns_enabled = false,
                       const String& mdns_hostname = "");

bool reset_managed_config_preserve_device_keys(AppState& state);

}  // namespace azt
