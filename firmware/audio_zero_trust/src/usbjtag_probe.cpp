#include <Arduino.h>
#include <cstring>
#include <memory>

static const uint8_t kMagic[4] = {'A', 'Z', 'T', '1'};

static uint32_t read_u32be(const uint8_t* p) {
  return (static_cast<uint32_t>(p[0]) << 24) |
         (static_cast<uint32_t>(p[1]) << 16) |
         (static_cast<uint32_t>(p[2]) << 8) |
         static_cast<uint32_t>(p[3]);
}

static void write_u32be(uint8_t* p, uint32_t v) {
  p[0] = static_cast<uint8_t>((v >> 24) & 0xFF);
  p[1] = static_cast<uint8_t>((v >> 16) & 0xFF);
  p[2] = static_cast<uint8_t>((v >> 8) & 0xFF);
  p[3] = static_cast<uint8_t>(v & 0xFF);
}

static uint32_t crc32_update(uint32_t crc, const uint8_t* data, size_t len) {
  crc = ~crc;
  for (size_t i = 0; i < len; ++i) {
    crc ^= data[i];
    for (int j = 0; j < 8; ++j) {
      uint32_t mask = -(crc & 1u);
      crc = (crc >> 1) ^ (0xEDB88320u & mask);
    }
  }
  return ~crc;
}

static size_t read_exact(uint8_t* out, size_t n, uint32_t timeout_ms) {
  const uint32_t start = millis();
  size_t got = 0;
  while (got < n) {
    while (Serial.available() && got < n) {
      int c = Serial.read();
      if (c < 0) break;
      out[got++] = static_cast<uint8_t>(c);
    }
    if (got >= n) break;
    if ((millis() - start) > timeout_ms) break;
    delay(1);
  }
  return got;
}

static void send_frame(const uint8_t* payload, uint32_t len) {
  uint8_t hdr[8];
  memcpy(hdr, kMagic, 4);
  write_u32be(hdr + 4, len);
  uint32_t crc = crc32_update(0, payload, len);
  uint8_t crc_be[4];
  write_u32be(crc_be, crc);

  Serial.write(hdr, sizeof(hdr));
  if (len > 0) Serial.write(payload, len);
  Serial.write(crc_be, sizeof(crc_be));
  Serial.flush();
}

void setup() {
  Serial.begin(115200);
  delay(200);
  const char* banner = "READY";
  send_frame(reinterpret_cast<const uint8_t*>(banner), 5);
}

void loop() {
  static uint32_t last_ready_ms = 0;
  if (!Serial.available()) {
    uint32_t now = millis();
    if (now - last_ready_ms > 2000) {
      const char* banner = "READY";
      send_frame(reinterpret_cast<const uint8_t*>(banner), 5);
      last_ready_ms = now;
    }
    delay(2);
    return;
  }

  uint8_t hdr[8];
  if (read_exact(hdr, sizeof(hdr), 1000) != sizeof(hdr)) {
    delay(2);
    return;
  }

  if (memcmp(hdr, kMagic, 4) != 0) {
    const char* msg = "ERR_MAGIC";
    send_frame(reinterpret_cast<const uint8_t*>(msg), 9);
    return;
  }

  const uint32_t len = read_u32be(hdr + 4);
  if (len > 65536) {
    const char* msg = "ERR_LEN";
    send_frame(reinterpret_cast<const uint8_t*>(msg), 7);
    return;
  }

  std::unique_ptr<uint8_t[]> payload(new uint8_t[len]);
  if (len > 0 && read_exact(payload.get(), len, 15000) != len) {
    const char* msg = "ERR_TIMEOUT_PAYLOAD";
    send_frame(reinterpret_cast<const uint8_t*>(msg), 19);
    return;
  }

  uint8_t crc_raw[4];
  if (read_exact(crc_raw, 4, 3000) != 4) {
    const char* msg = "ERR_TIMEOUT_CRC";
    send_frame(reinterpret_cast<const uint8_t*>(msg), 15);
    return;
  }
  const uint32_t got_crc = read_u32be(crc_raw);
  const uint32_t calc_crc = crc32_update(0, payload.get(), len);
  if (got_crc != calc_crc) {
    const char* msg = "ERR_CRC";
    send_frame(reinterpret_cast<const uint8_t*>(msg), 7);
    return;
  }

  // strict request/response: only respond after full request frame is received+validated
  char ok[32];
  int n = snprintf(ok, sizeof(ok), "OK:%lu", static_cast<unsigned long>(len));
  if (n < 0) return;
  send_frame(reinterpret_cast<const uint8_t*>(ok), static_cast<uint32_t>(n));
}
