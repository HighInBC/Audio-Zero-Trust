#include <Arduino.h>
#include <Wire.h>

namespace {

struct PinPair {
  int sda;
  int scl;
};

// Candidate pin pairs to probe. Includes common Atom defaults and likely Echo Base mappings.
constexpr PinPair kPairs[] = {
    {25, 21},
    {26, 32},
    {32, 26},
    {21, 22},
    {22, 21},
    {19, 22},
    {18, 19},
};

bool ping_addr(uint8_t addr) {
  Wire.beginTransmission(addr);
  return Wire.endTransmission() == 0;
}

void scan_pair(const PinPair& p) {
  Serial.printf("I2C_PROBE begin sda=%d scl=%d\n", p.sda, p.scl);
  Wire.end();
  delay(5);
  Wire.begin(p.sda, p.scl, 100000);
  delay(20);

  bool any = false;
  for (uint8_t addr = 0x03; addr <= 0x77; ++addr) {
    if (ping_addr(addr)) {
      any = true;
      Serial.printf("I2C_PROBE hit sda=%d scl=%d addr=0x%02X\n", p.sda, p.scl, addr);
    }
  }

  bool es8311 = ping_addr(0x18);
  bool expander_43 = ping_addr(0x43);
  bool expander_44 = ping_addr(0x44);
  bool expander_45 = ping_addr(0x45);

  Serial.printf(
      "I2C_PROBE summary sda=%d scl=%d any=%d es8311@0x18=%d pi4ioe@0x43=%d 0x44=%d 0x45=%d\n",
      p.sda,
      p.scl,
      any ? 1 : 0,
      es8311 ? 1 : 0,
      expander_43 ? 1 : 0,
      expander_44 ? 1 : 0,
      expander_45 ? 1 : 0);
}

}  // namespace

void setup() {
  Serial.begin(115200);
  delay(600);
  Serial.println("ECHO_BASE_I2C_PROBE start");

  for (const auto& pair : kPairs) {
    scan_pair(pair);
    delay(120);
  }

  Serial.println("ECHO_BASE_I2C_PROBE done");
}

void loop() {
  static uint32_t n = 0;
  delay(2000);
  ++n;
  Serial.printf("ECHO_BASE_I2C_PROBE heartbeat=%lu\n", static_cast<unsigned long>(n));
  if ((n % 5) == 0) {
    for (const auto& pair : kPairs) {
      scan_pair(pair);
      delay(80);
    }
  }
}
