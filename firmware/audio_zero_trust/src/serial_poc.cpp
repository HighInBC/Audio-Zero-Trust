#include <Arduino.h>

void setup() {
  Serial.begin(115200);
  delay(250);

  Serial.println("[POC] setup begin");
  Serial.printf("[POC] ARDUINO_USB_MODE=%d ARDUINO_USB_CDC_ON_BOOT=%d\n", ARDUINO_USB_MODE, ARDUINO_USB_CDC_ON_BOOT);
  Serial.println("[POC] If you can read this, USB CDC serial is working.");
}

void loop() {
  static uint32_t n = 0;
  Serial.printf("[POC] heartbeat %lu uptime_ms=%lu\n", static_cast<unsigned long>(n++), static_cast<unsigned long>(millis()));
  delay(1000);
}
