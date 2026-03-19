#include "azt_serial_control.h"

#include "azt_config.h"
#include "azt_http_api.h"

namespace azt {

void clear_serial_config_rx_state(SerialControlState& serial_state) {
  serial_state.config_mode = false;
  serial_state.config_len_mode = false;
  serial_state.config_expected_len = 0;
  serial_state.config_last_rx_ms = 0;
  serial_state.config_buf = "";
}

bool is_serial_config_rx_timed_out(const SerialControlState& serial_state,
                                   uint32_t now_ms,
                                   uint32_t timeout_ms) {
  return serial_state.config_last_rx_ms > 0 && (now_ms - serial_state.config_last_rx_ms) > timeout_ms;
}

String format_config_apply_lock_error_line() {
  return String("AZT_CONFIG_APPLY code=503 body={\"ok\":false,\"error\":\"ERR_STATE_LOCK\"}");
}

String format_recovery_reset_result_line(bool lock_acquired, bool reset_ok) {
  if (!lock_acquired) return String("AZT_RECOVERY_RESET_CONFIG ERR_LOCK");
  return String(reset_ok ? "AZT_RECOVERY_RESET_CONFIG OK" : "AZT_RECOVERY_RESET_CONFIG ERR");
}

SerialCommandKind classify_serial_command(const String& line) {
  if (line.startsWith("AZT_CONFIG_BEGIN_LEN ")) return SerialCommandKind::kConfigBeginLen;
  if (line == "AZT_CONFIG_BEGIN") return SerialCommandKind::kConfigBeginLegacy;
  if (line == "AZT_RECOVERY_RESET_CONFIG") return SerialCommandKind::kRecoveryReset;
  return SerialCommandKind::kUnknown;
}

String handle_config_mode_line_command(const String& line, SerialControlState& serial_state) {
  if (line == "AZT_CONFIG_END") {
    clear_serial_config_rx_state(serial_state);
    return String("AZT_CONFIG_APPLY code=400 body={\"ok\":false,\"error\":\"ERR_CONFIG_FRAMING\",\"detail\":\"length-prefixed mode required\"}");
  }
  return String();
}

bool parse_config_begin_len_command(const String& line,
                                    uint32_t now_ms,
                                    SerialControlState& serial_state,
                                    size_t& out_expected_len,
                                    String& out_error_line,
                                    size_t max_config_bytes) {
  out_expected_len = 0;
  out_error_line = "";
  if (!line.startsWith("AZT_CONFIG_BEGIN_LEN ")) return false;

  String v = line.substring(String("AZT_CONFIG_BEGIN_LEN ").length());
  v.trim();
  long n = v.toInt();
  if (n <= 0 || static_cast<size_t>(n) > max_config_bytes) {
    out_error_line = String("AZT_CONFIG_BEGIN_LEN ERR bytes=") + String(n) +
                     String(" max=") + String(static_cast<unsigned>(max_config_bytes));
    return true;
  }

  serial_state.config_mode = true;
  serial_state.config_len_mode = true;
  serial_state.config_expected_len = static_cast<size_t>(n);
  serial_state.config_last_rx_ms = now_ms;
  serial_state.config_buf = "";
  serial_state.config_buf.reserve(static_cast<size_t>(n) + 16);
  out_expected_len = serial_state.config_expected_len;
  return true;
}

SerialConfigRxStep consume_config_payload_chunk(SerialControlState& serial_state,
                                                const String& chunk,
                                                uint32_t now_ms,
                                                uint32_t timeout_ms) {
  SerialConfigRxStep step{};

  if (chunk.length() > 0 && serial_state.config_buf.length() < serial_state.config_expected_len) {
    size_t room = serial_state.config_expected_len - serial_state.config_buf.length();
    if (room > 0) {
      String take = chunk.substring(0, static_cast<unsigned>(room));
      serial_state.config_buf += take;
      serial_state.config_last_rx_ms = now_ms;
    }
  }

  if (serial_state.config_buf.length() >= serial_state.config_expected_len) {
    step.reached_expected_len = true;
    return step;
  }

  step.timed_out = is_serial_config_rx_timed_out(serial_state, now_ms, timeout_ms);
  return step;
}

void handle_serial_control(AppState& state,
                           SemaphoreHandle_t state_mu,
                           SerialControlState& serial_state) {
  static constexpr size_t kMaxConfigBytes = 64 * 1024;
  static constexpr uint32_t kConfigRxTimeoutMs = 30000;

  auto apply_buffered_config = [&]() {
    if (xSemaphoreTake(state_mu, pdMS_TO_TICKS(1000)) == pdTRUE) {
      auto r = apply_config_json_from_serial(state, serial_state.config_buf);
      Serial.printf("AZT_CONFIG_APPLY code=%d body=%s\n", r.code, r.body.c_str());
      xSemaphoreGive(state_mu);
    } else {
      Serial.println(format_config_apply_lock_error_line());
    }
    clear_serial_config_rx_state(serial_state);
  };

  if (serial_state.config_mode && serial_state.config_len_mode) {
    String chunk;
    while (Serial.available() && serial_state.config_buf.length() < serial_state.config_expected_len) {
      int c = Serial.read();
      if (c < 0) break;
      chunk += static_cast<char>(c);
    }

    SerialConfigRxStep step = consume_config_payload_chunk(serial_state, chunk, millis(), kConfigRxTimeoutMs);
    if (step.reached_expected_len) {
      apply_buffered_config();
      return;
    }

    if (step.timed_out) {
      Serial.printf("AZT_CONFIG_APPLY code=408 body={\"ok\":false,\"error\":\"ERR_CONFIG_TIMEOUT\",\"detail\":\"serial config payload timeout\"}\n");
      clear_serial_config_rx_state(serial_state);
    }
    return;
  }

  if (!Serial.available()) return;

  String line = Serial.readStringUntil('\n');
  line.trim();

  if (serial_state.config_mode) {
    // Length-prefixed mode only; ignore line-mode framing while waiting for bytes.
    String response = handle_config_mode_line_command(line, serial_state);
    if (response.length() > 0) Serial.println(response);
    return;
  }

  SerialCommandKind cmd = classify_serial_command(line);
  if (cmd == SerialCommandKind::kConfigBeginLen) {
    size_t expected_len = 0;
    String begin_len_error;
    (void)parse_config_begin_len_command(line, millis(), serial_state, expected_len, begin_len_error, kMaxConfigBytes);
    if (begin_len_error.length() > 0) {
      Serial.println(begin_len_error);
      return;
    }
    Serial.printf("AZT_CONFIG_BEGIN_LEN OK bytes=%u\n", static_cast<unsigned>(expected_len));
    return;
  }

  if (cmd == SerialCommandKind::kConfigBeginLegacy) {
    Serial.printf("AZT_CONFIG_BEGIN ERR length-prefixed mode required (use AZT_CONFIG_BEGIN_LEN <bytes>)\n");
    return;
  }

  if (cmd == SerialCommandKind::kRecoveryReset) {
    if (xSemaphoreTake(state_mu, pdMS_TO_TICKS(1000)) == pdTRUE) {
      bool ok = reset_managed_config_preserve_device_keys(state);
      Serial.println(format_recovery_reset_result_line(true, ok));
      xSemaphoreGive(state_mu);
    } else {
      Serial.println(format_recovery_reset_result_line(false, false));
    }
    return;
  }
}

}  // namespace azt
