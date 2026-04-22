#pragma once

#include <stdint.h>
#include <stddef.h>

namespace azt::constants::audio {

// User-configurable audio gain ranges.
constexpr uint8_t kPreampGainMin = 1;
constexpr uint8_t kPreampGainMax = 8;
constexpr uint8_t kAdcGainMin = 0;
constexpr uint8_t kAdcGainMax = 255;

// Defaults.
constexpr uint8_t kDefaultPreampGain = 2;
constexpr uint8_t kDefaultAdcGain = 248;
constexpr uint32_t kDefaultSampleRateHz = 16000;
constexpr uint8_t kDefaultChannels = 1;
constexpr uint8_t kDefaultSampleWidthBytes = 2;

// Echo Base / ES8311 interface.
constexpr uint8_t kEs8311I2cAddress = 0x18;
constexpr uint8_t kEs8311RegPreampGain = 0x16;
constexpr uint8_t kEs8311RegAdcGain = 0x17;
constexpr uint32_t kEchoBaseI2cClockHz = 100000U;

// Timing.
constexpr uint32_t kCodecResetDelayMs = 20;
constexpr uint32_t kEchoBaseProbeDelayMs = 10;
constexpr uint16_t kEchoBaseProbeAttempts = 20;
constexpr uint32_t kEchoBaseProbeRetryDelayMs = 25;

// Reused validation error details.
constexpr const char kPreampRangeDetail[] = "audio.preamp_gain must be 1..8";
constexpr const char kAdcRangeDetail[] = "audio.adc_gain must be 0..255";

}  // namespace azt::constants::audio

namespace azt::constants::pins {

#if CONFIG_IDF_TARGET_ESP32S3
constexpr int kEchoBaseI2cSda = 45;
constexpr int kEchoBaseI2cScl = 0;
constexpr int kEchoBaseI2sBck = 17;
constexpr int kEchoBaseI2sWs = 3;
constexpr int kEchoBaseI2sDataOut = 48;
constexpr int kEchoBaseI2sDataIn = 4;
#else
constexpr int kEchoBaseI2cSda = 25;
constexpr int kEchoBaseI2cScl = 21;
constexpr int kEchoBaseI2sBck = 33;
constexpr int kEchoBaseI2sWs = 19;
constexpr int kEchoBaseI2sDataOut = 22;
constexpr int kEchoBaseI2sDataIn = 23;
#endif

}  // namespace azt::constants::pins

namespace azt::constants::runtime {

constexpr uint32_t kSerialBaud = 115200;
constexpr uint32_t kBootDelayMs = 200;
constexpr uint32_t kUsbRxBufferSize = 8192;

constexpr uint32_t kStateLockWaitMsFast = 200;
constexpr uint32_t kStateLockWaitMsSlow = 4000;
constexpr uint32_t kIdleLoopDelayMs = 2;

// Wi-Fi recovery policy: if STA remains disconnected for long enough despite reconnect
// attempts, force a reboot to recover stuck radio/network state.
constexpr uint32_t kWifiMaintainIntervalMs = 5000;
constexpr uint32_t kWifiSoftReconnectTimeoutMs = 5000;
constexpr uint32_t kWifiHardReconnectTimeoutMs = 8000;
constexpr uint32_t kWifiHardReconnectEveryFailures = 4;
constexpr uint32_t kWifiRecoveryRebootAfterMs = 180000;  // 3 minutes
constexpr uint32_t kWifiRecoveryMinReconnectFailures = 8;

constexpr uint16_t kStreamPort = 8081;
constexpr uint16_t kApiTlsPort = 8443;

constexpr uint32_t kTaskStackStreamServer = 8192;
constexpr uint32_t kTaskPriorityNormal = 1;
constexpr uint32_t kTaskCore0 = 0;

constexpr uint32_t kTaskStackMicReader = 4096;
constexpr UBaseType_t kTaskPriorityMicReader = 2;
constexpr uint32_t kTaskStackStreamWorker = 12288;
constexpr uint32_t kMicReaderShutdownDelayMs = 10;

constexpr uint32_t kTaskStackSigner = 8192;
constexpr uint32_t kSignerStopAckWaitMs = 250;
constexpr uint32_t kSignerDeleteWaitMs = 200;
constexpr uint32_t kSignerDeletePollMs = 5;

namespace ota {
constexpr size_t kFlashSectorBytes = 4096;
constexpr size_t kHeaderMaxBytes = 4096;
constexpr uint32_t kReadChunkTimeoutMs = 5000;
constexpr uint32_t kQueueStopSendWaitMs = 50;
constexpr uint32_t kQueuePushWaitMs = 200;
constexpr uint32_t kEraseWaitMs = 90000;
constexpr uint32_t kWriterQueueDepth = 6;
constexpr uint32_t kTaskStackErase = 6144;
constexpr uint32_t kTaskStackWriter = 8192;
}  // namespace ota

}  // namespace azt::constants::runtime
