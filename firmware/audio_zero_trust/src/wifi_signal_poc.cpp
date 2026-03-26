#include <Arduino.h>
#include <WiFi.h>
#include <HTTPClient.h>

static const char* kSsid = "REPLACE_WITH_WIFI_SSID";
static const char* kPass = "REPLACE_WITH_WIFI_PASSWORD";
static const char* kPingUrlBase = "http://192.168.1.73:8088/ping";

void setup() {
  WiFi.mode(WIFI_STA);
  WiFi.begin(kSsid, kPass);
}

void loop() {
  if (WiFi.status() == WL_CONNECTED) {
    HTTPClient http;
    String url = String(kPingUrlBase) +
                 "?mac=" + WiFi.macAddress() +
                 "&ip=" + WiFi.localIP().toString() +
                 "&uptime_ms=" + String((unsigned long)millis());
    http.begin(url);
    http.setTimeout(1500);
    http.GET();
    http.end();
  }
  delay(2000);
}
