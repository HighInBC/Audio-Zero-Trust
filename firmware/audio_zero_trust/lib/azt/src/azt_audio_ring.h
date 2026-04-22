#pragma once

#include <Arduino.h>
#include <array>
#include <cstddef>
#include <cstdint>

#include "azt_app_state.h"

namespace azt {

constexpr size_t kMicFrameBytes = 1024;
// 16kHz * 2 bytes/sample * 1ch = 32000 bytes/sec -> 32 * 1024-byte frames ~= 1.024s
constexpr size_t kMicRingFrames = 32;

struct MicFrame {
  std::array<uint8_t, kMicFrameBytes> data{};
  size_t len = 0;
};

struct MicIngressStats {
  uint64_t i2s_fail = 0;
  uint64_t i2s_empty = 0;
  uint64_t read_wait_us = 0;
  uint64_t dropped_newest = 0;
};

struct MicRing {
  std::array<MicFrame, kMicRingFrames> slots{};
  size_t head = 0;
  size_t tail = 0;
  size_t count = 0;
  size_t high_water = 0;
  MicIngressStats stats{};
  volatile bool stop = false;
  portMUX_TYPE mux = portMUX_INITIALIZER_UNLOCKED;

  // Always-on MQTT RMS state (updated by mic reader task).
  bool mqtt_rms_enabled = false;
  uint16_t mqtt_rms_window_seconds = 10;
  uint32_t sample_rate_hz = 16000;
  uint64_t mqtt_rms_window_start_us = 0;
  double mqtt_rms_sum_sq = 0.0;
  uint64_t mqtt_rms_sample_count = 0;
  float mqtt_rms_dbfs_min = 0.0f;
  float mqtt_rms_dbfs_max = 0.0f;
  bool mqtt_rms_have_frame_stats = false;

  // Stream-stall accounting should only include drops while stream is active.
  bool stream_active = false;
};

bool mic_ring_push_drop_newest(MicRing& rb, const uint8_t* data, size_t len);
bool mic_ring_pop(MicRing& rb, MicFrame& out);
size_t mic_ring_count(MicRing& rb);
MicIngressStats mic_ring_snapshot_stats(MicRing& rb);
uint64_t mic_ring_take_dropped_newest(MicRing& rb);

void mic_reader_task_entry(void* arg);

void mic_ring_apply_mqtt_config(MicRing& rb, const AppState& state);
void mic_ring_set_stream_active(MicRing& rb, bool active);
void mic_ring_reset_dropped_newest(MicRing& rb);
void set_shared_mic_ring(MicRing* rb);
MicRing* get_shared_mic_ring();

}  // namespace azt
