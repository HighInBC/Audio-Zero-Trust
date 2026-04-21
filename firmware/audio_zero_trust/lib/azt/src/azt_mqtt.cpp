#include "azt_mqtt.h"

#include <ArduinoJson.h>
#include <esp_log.h>
#include <esp_timer.h>
#include <mqtt_client.h>

namespace azt {

namespace {

static esp_mqtt_client_handle_t g_client = nullptr;
static bool g_connected = false;
static String g_topic;
static String g_url;
static String g_username;
static String g_password;
static String g_device_label;
static String g_device_fp;

static constexpr const char* kTag = "AZT_MQTT";

static void stop_client() {
  if (g_client) {
    esp_mqtt_client_stop(g_client);
    esp_mqtt_client_destroy(g_client);
    g_client = nullptr;
  }
  g_connected = false;
}

static void mqtt_event_handler(void* /*handler_args*/, esp_event_base_t /*base*/, int32_t event_id, void* /*event_data*/) {
  if (event_id == MQTT_EVENT_CONNECTED) {
    g_connected = true;
  } else if (event_id == MQTT_EVENT_DISCONNECTED) {
    g_connected = false;
  }
}

}  // namespace

void mqtt_apply_config(const AppState& state) {
  String url = state.mqtt_broker_url;
  String user = state.mqtt_username;
  String pass = state.mqtt_password;
  String topic = state.mqtt_audio_rms_topic;
  url.trim();
  user.trim();
  pass.trim();
  topic.trim();

  g_device_label = state.device_label;
  g_device_fp = state.device_sign_fingerprint_hex;

  if (url.length() == 0 || topic.length() == 0) {
    g_topic = "";
    g_url = "";
    g_username = "";
    g_password = "";
    stop_client();
    return;
  }

  if (g_client && g_url == url && g_username == user && g_password == pass && g_topic == topic) {
    return;
  }

  stop_client();

  esp_mqtt_client_config_t cfg = {};
  cfg.uri = url.c_str();
  cfg.username = user.length() > 0 ? user.c_str() : nullptr;
  cfg.password = pass.length() > 0 ? pass.c_str() : nullptr;

  g_client = esp_mqtt_client_init(&cfg);
  if (!g_client) {
    ESP_LOGE(kTag, "init failed");
    return;
  }

  esp_mqtt_client_register_event(g_client, MQTT_EVENT_ANY, mqtt_event_handler, nullptr);
  if (esp_mqtt_client_start(g_client) != ESP_OK) {
    ESP_LOGE(kTag, "start failed");
    stop_client();
    return;
  }

  g_url = url;
  g_username = user;
  g_password = pass;
  g_topic = topic;
}

bool mqtt_is_enabled() {
  return g_client != nullptr && g_topic.length() > 0;
}

void mqtt_publish_audio_rms(float rms_dbfs, float rms_dbfs_min, float rms_dbfs_max, uint16_t window_seconds, uint32_t sample_rate_hz) {
  static uint32_t last_skip_log_ms = 0;
  if (!g_client || !g_connected || g_topic.length() == 0) {
    uint32_t now_ms = static_cast<uint32_t>(esp_timer_get_time() / 1000ULL);
    if (now_ms - last_skip_log_ms >= 5000U) {
      last_skip_log_ms = now_ms;
      ESP_LOGW(kTag, "publish skipped client=%d connected=%d topic_len=%u", g_client ? 1 : 0, g_connected ? 1 : 0, static_cast<unsigned>(g_topic.length()));
    }
    return;
  }

  JsonDocument doc;
  doc["schema"] = "azt.audio_rms.v1";
  doc["rms_dbfs"] = rms_dbfs;
  doc["rms_dbfs_min"] = rms_dbfs_min;
  doc["rms_dbfs_max"] = rms_dbfs_max;
  doc["window_seconds"] = static_cast<uint32_t>(window_seconds > 0 ? window_seconds : 10);
  doc["sample_rate_hz"] = sample_rate_hz;
  doc["device_label"] = g_device_label;
  doc["device_sign_fingerprint_hex"] = g_device_fp;
  doc["ts_epoch_ms"] = static_cast<unsigned long long>(esp_timer_get_time() / 1000ULL);

  String payload;
  serializeJson(doc, payload);
  int msg_id = esp_mqtt_client_publish(g_client, g_topic.c_str(), payload.c_str(), payload.length(), 0, 0);
  ESP_LOGI(kTag, "published rms topic=%s msg_id=%d dbfs=%.2f min=%.2f max=%.2f", g_topic.c_str(), msg_id, rms_dbfs, rms_dbfs_min, rms_dbfs_max);
}

}  // namespace azt
