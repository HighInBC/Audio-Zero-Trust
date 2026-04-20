#pragma once

#include <WiFiClient.h>

#include <vector>

#include "azt_app_state.h"

namespace azt {

struct TelemetrySnapshotV1;

struct StreamCtx {
  uint8_t audio_key[32];
  uint8_t nonce_prefix[4];
  uint8_t chain_key[32];
  uint8_t chain_genesis_secret[32];
  uint8_t chain_nonce_hash[32];
  uint8_t v_prev[32];
  uint32_t seq;
};

int parse_seconds_from_path(const String& path);
bool parse_signbench_from_path(const String& path);
int parse_drop_test_frames_from_path(const String& path);

// Testable runtime policy helpers.
uint32_t max_contiguous_drop_frames_for_config(uint32_t frame_samples,
                                               uint32_t max_contiguous_drop_ms = 10000,
                                               uint32_t sample_rate_hz = 16000);
bool should_disconnect_for_contiguous_drop(uint32_t contiguous_drop_frames,
                                           uint32_t frame_samples,
                                           uint32_t max_contiguous_drop_ms = 10000,
                                           uint32_t sample_rate_hz = 16000);
void account_drop_event(uint32_t drop_frames,
                        uint32_t& pending_dropped_frames,
                        uint64_t& dropped_frames_total,
                        uint32_t& contiguous_drop_frames);
bool apply_drop_and_check_stall(uint32_t drop_frames,
                                uint32_t frame_samples,
                                uint32_t& pending_dropped_frames,
                                uint64_t& dropped_frames_total,
                                uint32_t& contiguous_drop_frames,
                                uint32_t max_contiguous_drop_ms = 10000,
                                uint32_t sample_rate_hz = 16000);

struct StreamLoopDecision {
  bool disconnect_for_stall = false;
  bool emit_drop_notice = false;
  bool skip_audio_send = false;
};

StreamLoopDecision evaluate_stream_loop_branch(bool had_ingress_drop,
                                               bool drop_test_active,
                                               bool low_write_capacity,
                                               bool send_failed,
                                               uint32_t contiguous_drop_frames,
                                               uint32_t frame_samples,
                                               uint32_t max_contiguous_drop_ms = 10000,
                                               uint32_t sample_rate_hz = 16000);

bool should_defer_drop_notice_for_backpressure(int available_for_write,
                                               int min_notice_write = 64);
bool is_low_write_capacity(int available_for_write,
                           int min_audio_write = 32);
uint32_t sig_checkpoint_interval_on_missed_response(uint32_t current,
                                                    uint32_t min_interval = 10,
                                                    uint32_t max_interval = 160);
uint32_t sig_checkpoint_interval_on_response(uint32_t current,
                                             uint32_t min_interval = 10);

struct TelemetryAccumulator {
  uint32_t samples = 0;
  uint64_t level_sum = 0;
  uint16_t level_min = 0xFFFF;
  uint16_t level_max = 0;
  uint16_t level_last = 0;
};

void telemetry_accumulate_level(TelemetryAccumulator& acc, uint16_t rb_level);
bool telemetry_window_ready(const TelemetryAccumulator& acc, uint32_t interval_blocks);
TelemetrySnapshotV1 telemetry_snapshot_from_acc(const TelemetryAccumulator& acc);
void telemetry_reset(TelemetryAccumulator& acc);

void send_json(WiFiClient& client, int code, const String& body);
void request_stream_shutdown();
void clear_stream_shutdown_request();

void set_active_stream_session_nonce(const String& nonce);
void clear_active_stream_session_nonce(const String& nonce);
bool request_stream_termination_by_nonce(const String& nonce,
                                         uint8_t reason_code,
                                         const String& reason_text);
bool consume_stream_termination_for_nonce(const String& nonce,
                                          uint8_t& out_reason_code,
                                          String& out_reason_text);
void handle_stream(WiFiClient& client,
                   int seconds,
                   const AppState& state,
                   const String& stream_auth_nonce,
                   bool signbench_each_chunk = false,
                   bool enable_telemetry = false,
                   int drop_test_frames = 0);

}  // namespace azt
