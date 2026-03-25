#include <Arduino.h>
#include <Wire.h>
#include <driver/i2s.h>

namespace {
constexpr int kSda = 25;
constexpr int kScl = 21;
constexpr uint8_t kEs8311Addr = 0x18;
constexpr int kSampleRate = 16000;
constexpr int kSeconds = 1;
constexpr size_t kBytesTarget = static_cast<size_t>(kSampleRate * kSeconds * 2);

uint8_t g_mic_gain = 1;   // ES8311 mic gain enum-ish register value
uint8_t g_adc_gain = 255; // ES8311 ADC gain register

bool i2c_ping(uint8_t addr) {
  Wire.beginTransmission(addr);
  return Wire.endTransmission() == 0;
}

bool i2c_write_reg(uint8_t addr, uint8_t reg, uint8_t val) {
  Wire.beginTransmission(addr);
  Wire.write(reg);
  Wire.write(val);
  return Wire.endTransmission() == 0;
}

void es8311_apply_gains() {
  i2c_write_reg(kEs8311Addr, 0x16, g_mic_gain);
  i2c_write_reg(kEs8311Addr, 0x17, g_adc_gain);
}

void es8311_init_minimal() {
  // Match m5stack/M5Atomic-EchoBase ES8311 init path as closely as practical.
  i2c_write_reg(kEs8311Addr, 0x00, 0x1F);  // reset
  delay(20);
  i2c_write_reg(kEs8311Addr, 0x00, 0x00);
  i2c_write_reg(kEs8311Addr, 0x00, 0x80);  // power on

  // Clock source from SCLK (MCLK-from-SCLK mode), 16kHz, resolution=32 in/out.
  i2c_write_reg(kEs8311Addr, 0x01, 0xBF);
  i2c_write_reg(kEs8311Addr, 0x02, 0x10);
  i2c_write_reg(kEs8311Addr, 0x03, 0x10);
  i2c_write_reg(kEs8311Addr, 0x04, 0x10);
  i2c_write_reg(kEs8311Addr, 0x05, 0x00);
  i2c_write_reg(kEs8311Addr, 0x06, 0x03);
  i2c_write_reg(kEs8311Addr, 0x07, 0x00);
  i2c_write_reg(kEs8311Addr, 0x08, 0xFF);

  // Slave serial port, I2S format, 32-bit slot width like upstream lib.
  i2c_write_reg(kEs8311Addr, 0x00, 0x80);
  i2c_write_reg(kEs8311Addr, 0x09, 0x10);
  i2c_write_reg(kEs8311Addr, 0x0A, 0x10);

  // Analog mic path + gains
  i2c_write_reg(kEs8311Addr, 0x14, 0x1A);  // analog mic, max PGA
  es8311_apply_gains();

  i2c_write_reg(kEs8311Addr, 0x0D, 0x01);
  i2c_write_reg(kEs8311Addr, 0x0E, 0x02);
  i2c_write_reg(kEs8311Addr, 0x12, 0x00);
  i2c_write_reg(kEs8311Addr, 0x13, 0x10);
  i2c_write_reg(kEs8311Addr, 0x1C, 0x6A);
  i2c_write_reg(kEs8311Addr, 0x37, 0x08);
}

void setup_i2s_internal_pdm() {
  i2s_config_t cfg{};
  cfg.mode = (i2s_mode_t)(I2S_MODE_MASTER | I2S_MODE_RX | I2S_MODE_PDM);
  cfg.sample_rate = kSampleRate;
  cfg.bits_per_sample = I2S_BITS_PER_SAMPLE_16BIT;
  cfg.channel_format = I2S_CHANNEL_FMT_ONLY_RIGHT;
  cfg.communication_format = I2S_COMM_FORMAT_STAND_I2S;
  cfg.intr_alloc_flags = ESP_INTR_FLAG_LEVEL1;
  cfg.dma_buf_count = 8;
  cfg.dma_buf_len = 256;

  i2s_pin_config_t pins{};
  pins.bck_io_num = GPIO_NUM_19;
  pins.ws_io_num = GPIO_NUM_33;
  pins.data_out_num = I2S_PIN_NO_CHANGE;
  pins.data_in_num = GPIO_NUM_23;

  i2s_driver_install(I2S_NUM_0, &cfg, 0, nullptr);
  i2s_set_pin(I2S_NUM_0, &pins);
  i2s_zero_dma_buffer(I2S_NUM_0);
}

void setup_i2s_echo_base() {
  i2s_config_t cfg{};
  // Mirror known-working M5Atomic-EchoBase mode: full-duplex configured,
  // even if we only read in this probe.
  cfg.mode = (i2s_mode_t)(I2S_MODE_MASTER | I2S_MODE_TX | I2S_MODE_RX);
  cfg.sample_rate = kSampleRate;
  cfg.bits_per_sample = I2S_BITS_PER_SAMPLE_16BIT;
  cfg.channel_format = I2S_CHANNEL_FMT_RIGHT_LEFT;
  cfg.communication_format = I2S_COMM_FORMAT_STAND_I2S;
  cfg.intr_alloc_flags = ESP_INTR_FLAG_LEVEL1;
  cfg.dma_buf_count = 8;
  cfg.dma_buf_len = 256;
  cfg.use_apll = false;
  cfg.fixed_mclk = 0;

  i2s_pin_config_t pins{};
  // Atom Echo pin map from M5Atomic-EchoBase example:
  // DIN=23 WS=19 DOUT=22 BCK=33
  pins.bck_io_num = GPIO_NUM_33;
  pins.ws_io_num = GPIO_NUM_19;
  pins.data_out_num = GPIO_NUM_22;
  pins.data_in_num = GPIO_NUM_23;

  i2s_driver_install(I2S_NUM_0, &cfg, 0, nullptr);
  i2s_set_pin(I2S_NUM_0, &pins);
  i2s_zero_dma_buffer(I2S_NUM_0);
  i2s_start(I2S_NUM_0);
}

void stream_pcm_capture(const char* source) {
  uint8_t buf[1024];
  size_t sent = 0;

  Serial.printf("PCM_META source=%s sample_rate=%d bits=16 channels=1 bytes=%u\n",
                source,
                kSampleRate,
                static_cast<unsigned>(kBytesTarget));
  Serial.printf("PCM_START %u\n", static_cast<unsigned>(kBytesTarget));

  while (sent < kBytesTarget) {
    size_t n = 0;
    size_t want = sizeof(buf);
    if (kBytesTarget - sent < want) want = kBytesTarget - sent;
    esp_err_t rc = i2s_read(I2S_NUM_0, buf, want, &n, pdMS_TO_TICKS(200));
    if (rc != ESP_OK || n == 0) {
      continue;
    }
    Serial.write(buf, n);
    sent += n;
  }
  Serial.printf("\nPCM_END bytes=%u\n", static_cast<unsigned>(sent));
}
}  // namespace

static bool g_use_echo_base = false;

void setup() {
  Serial.begin(115200);
  delay(600);

  Wire.begin(kSda, kScl, 100000);
  delay(20);

  bool has_es8311 = i2c_ping(kEs8311Addr);
  g_use_echo_base = has_es8311;
  Serial.printf("PCM_PROBE i2c_sda=%d i2c_scl=%d es8311_0x18=%d\n", kSda, kScl, has_es8311 ? 1 : 0);

  if (has_es8311) {
    es8311_init_minimal();
    setup_i2s_echo_base();
  } else {
    setup_i2s_internal_pdm();
  }

  delay(150);
  Serial.println("PCM_PROBE ready");
}

void loop() {
  if (Serial.available()) {
    String cmd = Serial.readStringUntil('\n');
    cmd.trim();
    cmd.toUpperCase();

    if (cmd == "CAPTURE") {
      stream_pcm_capture(g_use_echo_base ? "echo_base" : "internal_pdm");
      return;
    }

    if (g_use_echo_base && cmd.startsWith("MICGAIN ")) {
      int v = cmd.substring(8).toInt();
      if (v < 0) v = 0;
      if (v > 255) v = 255;
      g_mic_gain = static_cast<uint8_t>(v);
      es8311_apply_gains();
      Serial.printf("PCM_CFG micgain=%u adcgain=%u\n", g_mic_gain, g_adc_gain);
      return;
    }

    if (g_use_echo_base && cmd.startsWith("ADCGAIN ")) {
      int v = cmd.substring(8).toInt();
      if (v < 0) v = 0;
      if (v > 255) v = 255;
      g_adc_gain = static_cast<uint8_t>(v);
      es8311_apply_gains();
      Serial.printf("PCM_CFG micgain=%u adcgain=%u\n", g_mic_gain, g_adc_gain);
      return;
    }

    if (cmd == "STATUS") {
      Serial.printf("PCM_STATUS source=%s micgain=%u adcgain=%u\n", g_use_echo_base ? "echo_base" : "internal_pdm", g_mic_gain, g_adc_gain);
      return;
    }
  }

  delay(20);
}
