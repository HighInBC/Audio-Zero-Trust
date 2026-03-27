#include <Arduino.h>

static bool rx_mode = false;
static size_t expected = 0;
static size_t received = 0;

static void logln(const String& s) {
  Serial.println(s);
  printf("%s\n", s.c_str());
}

void setup() {
  Serial.begin(115200);
  delay(200);
  logln("[USBJTAG_PROBE] boot");
  logln(String("[USBJTAG_PROBE] ARDUINO_USB_MODE=") + ARDUINO_USB_MODE +
        " ARDUINO_USB_CDC_ON_BOOT=" + ARDUINO_USB_CDC_ON_BOOT);
  logln("[USBJTAG_PROBE] send: LEN <n> then raw bytes");
}

void loop() {
  static String line;
  while (Serial.available()) {
    int c = Serial.read();
    if (c < 0) break;
    char ch = static_cast<char>(c);

    if (rx_mode) {
      received++;
      if ((received % 512) == 0) {
        logln(String("[USBJTAG_PROBE] progress ") + received + "/" + expected);
      }
      if (received >= expected) {
        logln(String("[USBJTAG_PROBE] complete ") + received + "/" + expected);
        rx_mode = false;
      }
      continue;
    }

    if (ch == '\r') continue;
    if (ch == '\n') {
      line.trim();
      if (line.startsWith("LEN ")) {
        long n = line.substring(4).toInt();
        if (n > 0) {
          expected = static_cast<size_t>(n);
          received = 0;
          rx_mode = true;
          logln(String("[USBJTAG_PROBE] begin ") + expected);
        } else {
          logln("[USBJTAG_PROBE] bad len");
        }
      } else if (line.length() > 0) {
        logln(String("[USBJTAG_PROBE] cmd ") + line);
      }
      line = "";
      continue;
    }
    line += ch;
    if (line.length() > 256) line = "";
  }

  static uint32_t last = 0;
  if (millis() - last > 2000) {
    last = millis();
    logln(String("[USBJTAG_PROBE] hb ms=") + millis());
  }
  delay(2);
}
