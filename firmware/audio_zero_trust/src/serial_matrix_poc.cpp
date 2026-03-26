#include <Arduino.h>
#include <WiFi.h>
#include <HTTPClient.h>

#ifndef SERIAL_MODE
#define SERIAL_MODE 1
#endif

static const char* kSsid = "REPLACE_WITH_WIFI_SSID";
static const char* kPass = "REPLACE_WITH_WIFI_PASSWORD";
static const char* kPingUrlBase = "http://192.168.1.73:8088/ping";

static void emit_line(const String& msg) {
#if SERIAL_MODE == 1
  Serial.println("[SERIAL_MODE=1 Serial] " + msg);
#elif SERIAL_MODE == 2
  Serial0.println("[SERIAL_MODE=2 Serial0] " + msg);
#elif SERIAL_MODE == 3
  printf("[SERIAL_MODE=3 printf] %s\n", msg.c_str());
#else
  Serial.println("[SERIAL_MODE=?] " + msg);
#endif
}

void setup() {
  Serial.begin(115200);
  Serial0.begin(115200);
  delay(150);
  emit_line("setup");

  WiFi.mode(WIFI_STA);
  WiFi.begin(kSsid, kPass);
}

void loop() {
  static uint32_t n = 0;
  emit_line("tick=" + String(n++));

  if (WiFi.status() == WL_CONNECTED) {
    HTTPClient http;
    String url = String(kPingUrlBase) +
                 "?mode=" + String(SERIAL_MODE) +
                 "&mac=" + WiFi.macAddress() +
                 "&ip=" + WiFi.localIP().toString() +
                 "&uptime_ms=" + String((unsigned long)millis());
    http.begin(url);
    http.setTimeout(1200);
    http.GET();
    http.end();
  }

  delay(2000);
}
