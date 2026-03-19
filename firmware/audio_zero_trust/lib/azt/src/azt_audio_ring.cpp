#include "azt_audio_ring.h"

#include <driver/i2s.h>
#include <esp_timer.h>

#include "azt_device_io.h"

namespace azt {

bool mic_ring_push_drop_newest(MicRing& rb, const uint8_t* data, size_t len) {
  bool pushed = false;
  portENTER_CRITICAL(&rb.mux);
  if (rb.count >= kMicRingFrames) {
    rb.stats.dropped_newest++;
  } else {
    MicFrame& slot = rb.slots[rb.head];
    memcpy(slot.data.data(), data, len);
    slot.len = len;
    rb.head = (rb.head + 1) % kMicRingFrames;
    rb.count++;
    if (rb.count > rb.high_water) rb.high_water = rb.count;
    pushed = true;
  }
  portEXIT_CRITICAL(&rb.mux);
  return pushed;
}

bool mic_ring_pop(MicRing& rb, MicFrame& out) {
  bool ok = false;
  portENTER_CRITICAL(&rb.mux);
  if (rb.count > 0) {
    out = rb.slots[rb.tail];
    rb.tail = (rb.tail + 1) % kMicRingFrames;
    rb.count--;
    ok = true;
  }
  portEXIT_CRITICAL(&rb.mux);
  return ok;
}

size_t mic_ring_count(MicRing& rb) {
  size_t c = 0;
  portENTER_CRITICAL(&rb.mux);
  c = rb.count;
  portEXIT_CRITICAL(&rb.mux);
  return c;
}

MicIngressStats mic_ring_snapshot_stats(MicRing& rb) {
  MicIngressStats s;
  portENTER_CRITICAL(&rb.mux);
  s = rb.stats;
  portEXIT_CRITICAL(&rb.mux);
  return s;
}

uint64_t mic_ring_take_dropped_newest(MicRing& rb) {
  uint64_t dropped = 0;
  portENTER_CRITICAL(&rb.mux);
  dropped = rb.stats.dropped_newest;
  rb.stats.dropped_newest = 0;
  portEXIT_CRITICAL(&rb.mux);
  return dropped;
}

void mic_reader_task_entry(void* arg) {
  MicRing* rb = reinterpret_cast<MicRing*>(arg);
  uint8_t mic_buf[kMicFrameBytes];

  while (!rb->stop) {
    const uint64_t t0 = static_cast<uint64_t>(esp_timer_get_time());
    size_t n = 0;
    esp_err_t rc = i2s_read(kI2SPort, mic_buf, sizeof(mic_buf), &n, pdMS_TO_TICKS(50));
    const uint64_t t1 = static_cast<uint64_t>(esp_timer_get_time());

    portENTER_CRITICAL(&rb->mux);
    rb->stats.read_wait_us += (t1 - t0);
    portEXIT_CRITICAL(&rb->mux);

    if (rc != ESP_OK) {
      portENTER_CRITICAL(&rb->mux);
      rb->stats.i2s_fail++;
      portEXIT_CRITICAL(&rb->mux);
      continue;
    }
    if (n == 0) {
      portENTER_CRITICAL(&rb->mux);
      rb->stats.i2s_empty++;
      portEXIT_CRITICAL(&rb->mux);
      continue;
    }

    mic_ring_push_drop_newest(*rb, mic_buf, n);
  }

  vTaskDelete(nullptr);
}

}  // namespace azt
