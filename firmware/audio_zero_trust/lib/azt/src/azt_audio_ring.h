#pragma once

#include <Arduino.h>
#include <array>
#include <cstddef>
#include <cstdint>

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
};

bool mic_ring_push_drop_newest(MicRing& rb, const uint8_t* data, size_t len);
bool mic_ring_pop(MicRing& rb, MicFrame& out);
size_t mic_ring_count(MicRing& rb);
MicIngressStats mic_ring_snapshot_stats(MicRing& rb);
uint64_t mic_ring_take_dropped_newest(MicRing& rb);

void mic_reader_task_entry(void* arg);

}  // namespace azt
