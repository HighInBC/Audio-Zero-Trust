#pragma once

#include <WiFiClient.h>

#include <vector>

#include "azt_stream.h"
#include "azt_stream_transport.h"

namespace azt {

constexpr uint8_t kBlockTypePcmAudio = 0x00;
constexpr uint8_t kBlockTypeSignature = 0x01;
constexpr uint8_t kBlockTypeDroppedFrames = 0x02;
constexpr uint8_t kBlockTypeTelemetrySnapshot = 0x03;

struct TelemetrySnapshotV1 {
  uint16_t window_blocks = 0;
  uint16_t rb_level_min = 0;
  uint16_t rb_level_max = 0;
  uint16_t rb_level_avg_q8 = 0;
  uint16_t rb_level_last = 0;
};

void encode_telemetry_snapshot_body_v1(const TelemetrySnapshotV1& t, std::vector<uint8_t>& out);

bool send_chunked(StreamTransport& transport, const uint8_t* data, size_t len);
bool send_chunked(WiFiClient& client, const uint8_t* data, size_t len);

bool encrypt_audio_chunk_and_chain(StreamCtx& sc,
                                   const uint8_t* pcm,
                                   size_t pcm_len,
                                   std::vector<uint8_t>& rec_out,
                                   uint8_t out_v_new[32]);

bool encrypt_signature_block_and_chain(StreamCtx& sc,
                                       uint32_t ref_seq,
                                       const uint8_t sig64[64],
                                       std::vector<uint8_t>& rec_out);

bool encrypt_dropped_frames_block_and_chain(StreamCtx& sc,
                                            uint16_t missed_frames,
                                            std::vector<uint8_t>& rec_out);

bool encrypt_telemetry_snapshot_block_and_chain(StreamCtx& sc,
                                                const TelemetrySnapshotV1& t,
                                                std::vector<uint8_t>& rec_out);

}  // namespace azt
