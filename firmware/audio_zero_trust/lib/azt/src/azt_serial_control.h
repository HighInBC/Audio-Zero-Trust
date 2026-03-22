#pragma once

#include <Arduino.h>
#include <freertos/semphr.h>

#include "azt_app_state.h"

namespace azt {

struct SerialControlState {
  bool config_mode = false;
  bool config_len_mode = false;
  size_t config_expected_len = 0;
  uint32_t config_last_rx_ms = 0;
  String config_buf;
};

void handle_serial_control(AppState& state,
                           SemaphoreHandle_t state_mu,
                           SerialControlState& serial_state);

// Testable helpers for serial-control branch behavior.
void clear_serial_config_rx_state(SerialControlState& serial_state);
bool is_serial_config_rx_timed_out(const SerialControlState& serial_state,
                                   uint32_t now_ms,
                                   uint32_t timeout_ms = 30000);
String format_config_apply_lock_error_line();
String format_recovery_reset_result_line(bool lock_acquired, bool reset_ok);

enum class SerialCommandKind {
  kUnknown,
  kConfigBeginLen,
  kConfigBeginLegacy,
  kRecoveryReset,
  kOtaApply,
};
SerialCommandKind classify_serial_command(const String& line);

// Parses line-mode command while in config_mode (waiting for length-prefixed bytes).
// Returns empty string when no response should be emitted.
String handle_config_mode_line_command(const String& line, SerialControlState& serial_state);

// Parses AZT_CONFIG_BEGIN_LEN command.
// Returns true on success and writes out_expected_len. On failure, out_error_line is populated.
bool parse_config_begin_len_command(const String& line,
                                    uint32_t now_ms,
                                    SerialControlState& serial_state,
                                    size_t& out_expected_len,
                                    String& out_error_line,
                                    size_t max_config_bytes = 64 * 1024);

struct SerialConfigRxStep {
  bool reached_expected_len = false;
  bool timed_out = false;
};

SerialConfigRxStep consume_config_payload_chunk(SerialControlState& serial_state,
                                                const String& chunk,
                                                uint32_t now_ms,
                                                uint32_t timeout_ms = 30000);

}  // namespace azt
