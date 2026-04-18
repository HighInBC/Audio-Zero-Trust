#pragma once

#include <Arduino.h>

#include "azt_app_state.h"

namespace azt {

void mqtt_apply_config(const AppState& state);
bool mqtt_is_enabled();
void mqtt_publish_audio_rms(float rms_dbfs, uint16_t window_seconds, uint32_t sample_rate_hz);

}  // namespace azt
