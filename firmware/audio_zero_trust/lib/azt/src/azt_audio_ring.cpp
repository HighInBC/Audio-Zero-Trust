#include "azt_audio_ring.h"

#include <driver/i2s.h>
#include <esp_timer.h>
#include <math.h>

#include "azt_device_io.h"
#include "azt_mqtt.h"

namespace azt {

namespace {
MicRing* g_shared_mic_ring = nullptr;
}

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

    if (rb->mqtt_rms_enabled && n >= 2) {
      const int16_t* s = reinterpret_cast<const int16_t*>(mic_buf);
      size_t sample_n = static_cast<size_t>(n / 2);
      double frame_sum_sq = 0.0;
      for (size_t i = 0; i < sample_n; i++) {
        double v = static_cast<double>(s[i]) / 32768.0;
        double vv = (v * v);
        frame_sum_sq += vv;
        rb->mqtt_rms_sum_sq += vv;
      }
      rb->mqtt_rms_sample_count += sample_n;

      double frame_rms = sample_n > 0 ? sqrt(frame_sum_sq / static_cast<double>(sample_n)) : 0.0;
      if (frame_rms < 1e-6) frame_rms = 1e-6;
      float frame_dbfs = static_cast<float>(20.0 * log10(frame_rms));
      if (frame_dbfs < -96.0f) frame_dbfs = -96.0f;
      if (!rb->mqtt_rms_have_frame_stats) {
        rb->mqtt_rms_dbfs_min = frame_dbfs;
        rb->mqtt_rms_dbfs_max = frame_dbfs;
        rb->mqtt_rms_have_frame_stats = true;
      } else {
        if (frame_dbfs < rb->mqtt_rms_dbfs_min) rb->mqtt_rms_dbfs_min = frame_dbfs;
        if (frame_dbfs > rb->mqtt_rms_dbfs_max) rb->mqtt_rms_dbfs_max = frame_dbfs;
      }

      uint64_t now_us = static_cast<uint64_t>(esp_timer_get_time());
      const uint64_t window_us = static_cast<uint64_t>(rb->mqtt_rms_window_seconds > 0 ? rb->mqtt_rms_window_seconds : 10) * 1000000ULL;
      if (rb->mqtt_rms_window_start_us == 0) rb->mqtt_rms_window_start_us = now_us;
      if (now_us - rb->mqtt_rms_window_start_us >= window_us) {
        double rms = rb->mqtt_rms_sample_count > 0 ? sqrt(rb->mqtt_rms_sum_sq / static_cast<double>(rb->mqtt_rms_sample_count)) : 0.0;
        if (rms < 1e-6) rms = 1e-6;
        float dbfs = static_cast<float>(20.0 * log10(rms));
        if (dbfs < -96.0f) dbfs = -96.0f;
        float dbfs_min = rb->mqtt_rms_have_frame_stats ? rb->mqtt_rms_dbfs_min : dbfs;
        float dbfs_max = rb->mqtt_rms_have_frame_stats ? rb->mqtt_rms_dbfs_max : dbfs;
        mqtt_publish_audio_rms(dbfs, dbfs_min, dbfs_max, rb->mqtt_rms_window_seconds, rb->sample_rate_hz);

        rb->mqtt_rms_window_start_us = now_us;
        rb->mqtt_rms_sum_sq = 0.0;
        rb->mqtt_rms_sample_count = 0;
        rb->mqtt_rms_have_frame_stats = false;
      }
    }
  }

  vTaskDelete(nullptr);
}

void mic_ring_apply_mqtt_config(MicRing& rb, const AppState& state) {
  rb.mqtt_rms_enabled = mqtt_is_enabled() && state.mqtt_broker_url.length() > 0 && state.mqtt_audio_rms_topic.length() > 0;
  rb.mqtt_rms_window_seconds = state.mqtt_rms_window_seconds > 0 ? state.mqtt_rms_window_seconds : 10;
  rb.sample_rate_hz = state.audio_sample_rate_hz > 0 ? state.audio_sample_rate_hz : 16000;
  Serial.printf("AZT_MQTT_RMS cfg enabled=%u broker_len=%u topic_len=%u window_s=%u sample_rate=%lu\n",
                static_cast<unsigned>(rb.mqtt_rms_enabled ? 1 : 0),
                static_cast<unsigned>(state.mqtt_broker_url.length()),
                static_cast<unsigned>(state.mqtt_audio_rms_topic.length()),
                static_cast<unsigned>(rb.mqtt_rms_window_seconds),
                static_cast<unsigned long>(rb.sample_rate_hz));
}

void set_shared_mic_ring(MicRing* rb) {
  g_shared_mic_ring = rb;
}

MicRing* get_shared_mic_ring() {
  return g_shared_mic_ring;
}

}  // namespace azt
