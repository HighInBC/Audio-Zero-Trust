#include <Arduino.h>
#include <WiFiServer.h>
#include <freertos/FreeRTOS.h>
#include <freertos/semphr.h>

#include "azt_app_state.h"
#include "azt_audio_ring.h"
#include "azt_constants.h"
#include "azt_config.h"
#include "azt_device_io.h"
#include "azt_discovery.h"
#include "azt_http_api.h"
#include "azt_serial_control.h"
#include "azt_https_server.h"
#include "azt_mqtt.h"

namespace {


azt::AppState g_state;
WiFiServer g_api_server(azt::kHttpPort);
WiFiServer g_stream_server(azt::constants::runtime::kStreamPort);
SemaphoreHandle_t g_state_mu = nullptr;
TaskHandle_t g_stream_task = nullptr;
TaskHandle_t g_mic_reader_task = nullptr;
bool g_http_servers_enabled = false;
String g_last_mqtt_sig;
azt::MicRing g_mic_ring;

azt::SerialControlState g_serial_state;

void log_boot_marker(const char* msg) {
  if (!msg) return;
  Serial.printf("[Serial] %s\n", msg);
}

void stream_server_task(void*) {
  for (;;) {
    WiFiClient client = g_stream_server.available();
    if (!client) {
      delay(azt::constants::runtime::kIdleLoopDelayMs);
      continue;
    }

    azt::AppState snapshot;
    if (xSemaphoreTake(g_state_mu, pdMS_TO_TICKS(azt::constants::runtime::kStateLockWaitMsFast)) != pdTRUE) {
      client.stop();
      continue;
    }
    snapshot = g_state;
    xSemaphoreGive(g_state_mu);

    azt::handle_client_stream_only(client, snapshot);
    client.stop();
  }
}

}  // namespace

void setup() {
#if CONFIG_IDF_TARGET_ESP32S3
  // Atom EchoS3R: increase USB serial RX buffer to reduce large-payload ingress stalls.
  // Old target (ESP32 Atom Echo) does not use this path.
  Serial.setRxBufferSize(azt::constants::runtime::kUsbRxBufferSize);
#endif
  Serial.begin(azt::constants::runtime::kSerialBaud);
  delay(azt::constants::runtime::kBootDelayMs);

  log_boot_marker("setup_start");
#if CONFIG_IDF_TARGET_ESP32S3
  Serial.printf("[Serial] usb_mode=%d cdc_on_boot=%d\n", ARDUINO_USB_MODE, ARDUINO_USB_CDC_ON_BOOT);
#endif

  g_state_mu = xSemaphoreCreateMutex();

  xSemaphoreTake(g_state_mu, portMAX_DELAY);
  azt::load_config_state(g_state);
  g_state.discovery_announcement_json = azt::build_discovery_announcement_json(g_state, azt::kHttpPort);
  azt::setup_wifi(g_state);
  azt::setup_time_sync(g_state);
  azt::mqtt_apply_config(g_state);
  g_last_mqtt_sig = g_state.mqtt_broker_url + "|" + g_state.mqtt_username + "|" + g_state.mqtt_password + "|" + g_state.mqtt_audio_rms_topic + "|" + String(g_state.mqtt_rms_window_seconds);
  xSemaphoreGive(g_state_mu);

  azt::setup_audio_input(g_state);
  azt::mic_ring_apply_mqtt_config(g_mic_ring, g_state);
  azt::set_shared_mic_ring(&g_mic_ring);
  if (xTaskCreatePinnedToCore(azt::mic_reader_task_entry,
                              "azt_mic_reader",
                              azt::constants::runtime::kTaskStackMicReader,
                              &g_mic_ring,
                              static_cast<UBaseType_t>(azt::constants::runtime::kTaskPriorityMicReader),
                              &g_mic_reader_task,
                              1) != pdPASS) {
    Serial.println("AZT_MIC failed_to_start_reader_task");
  }

  bool https_ok = azt::start_https_api_server(&g_state, g_state_mu, azt::constants::runtime::kApiTlsPort);

  if (https_ok) {
    // Security policy: plaintext HTTP is never allowed for general API routes.
    // HTTP listeners are enabled only as a narrow transport for hardened OTA/stream paths.
    g_http_servers_enabled = true;
    g_api_server.begin();
    g_stream_server.begin();

    xTaskCreatePinnedToCore(stream_server_task,
                            "azt_stream_server",
                            azt::constants::runtime::kTaskStackStreamServer,
                            nullptr,
                            static_cast<UBaseType_t>(azt::constants::runtime::kTaskPriorityNormal),
                            &g_stream_task,
                            static_cast<BaseType_t>(azt::constants::runtime::kTaskCore0));

    Serial.printf("AZT_HTTP limited_endpoints api_port=%u stream_port=%u\n", azt::kHttpPort, azt::constants::runtime::kStreamPort);
    log_boot_marker("http_server_started_limited");
    Serial.printf("AZT_HTTPS api_tls_port=%u\n", azt::constants::runtime::kApiTlsPort);
  } else {
    g_http_servers_enabled = false;
    Serial.println("AZT_NET tls_not_configured: network API/stream/OTA disabled; serial-only mode");
  }
}

void loop() {
  if (xSemaphoreTake(g_state_mu, pdMS_TO_TICKS(azt::constants::runtime::kStateLockWaitMsFast)) == pdTRUE) {
    // During serial config payload ingestion, reduce background serial chatter and work.
    if (!g_serial_state.config_mode) {
      azt::maybe_maintain_wifi(g_state);
      azt::maybe_refresh_time_sync(g_state);
      azt::maybe_broadcast_discovery_announcement(g_state);
    }
    String mqtt_sig = g_state.mqtt_broker_url + "|" + g_state.mqtt_username + "|" + g_state.mqtt_password + "|" + g_state.mqtt_audio_rms_topic + "|" + String(g_state.mqtt_rms_window_seconds);
    if (mqtt_sig != g_last_mqtt_sig) {
      azt::mqtt_apply_config(g_state);
      azt::mic_ring_apply_mqtt_config(g_mic_ring, g_state);
      g_last_mqtt_sig = mqtt_sig;
    }
    if (azt::mic_ring_take_reinit_request(g_mic_ring)) {
      Serial.println("AZT_AUDIO_DEGRADED action=reinit");
      azt::reinitialize_audio_input(g_state);
    }
    xSemaphoreGive(g_state_mu);
  }

  azt::handle_serial_control(g_state, g_state_mu, g_serial_state);

  if (!g_http_servers_enabled) {
    delay(azt::constants::runtime::kIdleLoopDelayMs);
    return;
  }

  WiFiClient client = g_api_server.available();
  if (!client) {
    delay(azt::constants::runtime::kIdleLoopDelayMs);
    return;
  }

  if (xSemaphoreTake(g_state_mu, pdMS_TO_TICKS(azt::constants::runtime::kStateLockWaitMsSlow)) != pdTRUE) {
    client.stop();
    return;
  }
  azt::handle_client_api_only(client, g_state);
  xSemaphoreGive(g_state_mu);
  client.stop();
}
