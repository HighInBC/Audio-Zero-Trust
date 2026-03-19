#pragma once

#include <Arduino.h>

#include "azt_app_state.h"

namespace azt {

String build_discovery_announcement_json(const AppState& state, uint16_t http_port);
size_t parse_authorized_listener_ips_csv(const String& csv, IPAddress* out, size_t max_out);
void maybe_broadcast_discovery_announcement(const AppState& state);

}  // namespace azt
