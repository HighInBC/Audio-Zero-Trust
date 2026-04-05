#include <Arduino.h>
#include <freertos/FreeRTOS.h>
#include <freertos/semphr.h>

#include "azt_app_state.h"
#include "azt_constants.h"
#include "azt_config.h"
#include "azt_device_io.h"
#include "azt_discovery.h"
#include "azt_serial_control.h"
#include "azt_https_server.h"

namespace {


azt::AppState g_state;
SemaphoreHandle_t g_state_mu = nullptr;

azt::SerialControlState g_serial_state;

void log_boot_marker(const char* msg) {
  if (!msg) return;
  Serial.printf("[Serial] %s\n", msg);
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
  g_state.discovery_announcement_json = azt::build_discovery_announcement_json(g_state, azt::constants::runtime::kApiTlsPort);
  azt::setup_wifi(g_state);
  azt::setup_time_sync(g_state);
  xSemaphoreGive(g_state_mu);

  azt::setup_audio_input(g_state);

  bool https_ok = azt::start_https_api_server(&g_state, g_state_mu, azt::constants::runtime::kApiTlsPort);
  bool https_stream_ok = azt::start_https_stream_server(&g_state, g_state_mu, azt::constants::runtime::kStreamTlsPort);
  if (https_ok) {
    Serial.printf("AZT_HTTPS api_tls_port=%u\n", azt::constants::runtime::kApiTlsPort);
  } else {
    Serial.println("AZT_HTTPS disabled (no tls cert/key configured)");
  }
  if (https_stream_ok) {
    Serial.printf("AZT_HTTPS stream_tls_port=%u\n", azt::constants::runtime::kStreamTlsPort);
  } else {
    Serial.println("AZT_HTTPS stream disabled");
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
    xSemaphoreGive(g_state_mu);
  }

  azt::handle_serial_control(g_state, g_state_mu, g_serial_state);

  delay(azt::constants::runtime::kIdleLoopDelayMs);
}
