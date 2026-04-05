#include "azt_stream_record.h"

#include <Arduino.h>

#include "azt_crypto.h"

namespace azt {

bool send_chunked(StreamTransport& transport, const uint8_t* data, size_t len) {
  if (transport.uses_http_chunk_transport()) {
    return transport.write_bytes(data, len);
  }
  char hdr[20];
  snprintf(hdr, sizeof(hdr), "%x\r\n", static_cast<unsigned>(len));
  if (!transport.write_text(hdr)) return false;
  if (!transport.write_bytes(data, len)) return false;
  if (!transport.write_text("\r\n")) return false;
  return true;
}

bool send_chunked(WiFiClient& client, const uint8_t* data, size_t len) {
  WiFiClientStreamTransport transport(client);
  return send_chunked(transport, data, len);
}

static bool encrypt_payload_and_chain(StreamCtx& sc,
                                      uint8_t block_type,
                                      const uint8_t* payload,
                                      size_t payload_len,
                                      bool encrypt_payload,
                                      std::vector<uint8_t>& rec_out,
                                      uint8_t out_v_new[32]) {
  rec_out.clear();
  sc.seq += 1;

  std::vector<uint8_t> body;
  uint8_t tag[16] = {0};
  uint8_t tag_len = 0;

  if (encrypt_payload) {
    uint8_t nonce[12];
    memcpy(nonce, sc.nonce_prefix, 4);
    nonce[4] = static_cast<uint8_t>((sc.seq >> 24) & 0xFF);
    nonce[5] = static_cast<uint8_t>((sc.seq >> 16) & 0xFF);
    nonce[6] = static_cast<uint8_t>((sc.seq >> 8) & 0xFF);
    nonce[7] = static_cast<uint8_t>(sc.seq & 0xFF);
    nonce[8] = 0;
    nonce[9] = 0;
    nonce[10] = 0;
    nonce[11] = 0;

    if (!aes256_gcm_encrypt(sc.audio_key, nonce, payload, payload_len, body, tag)) {
      return false;
    }
    tag_len = 16;
  } else {
    body.insert(body.end(), payload, payload + payload_len);
    tag_len = 0;
  }

  std::vector<uint8_t> core;
  core.reserve(4 + 1 + 4 + 1 + body.size() + tag_len);
  append_u32_be(core, sc.seq);
  core.push_back(block_type);
  append_u32_be(core, static_cast<uint32_t>(body.size()));
  core.push_back(tag_len);
  core.insert(core.end(), body.begin(), body.end());
  if (tag_len > 0) core.insert(core.end(), tag, tag + tag_len);

  std::vector<uint8_t> hmsg;
  hmsg.reserve(13 + 32 + core.size());
  static const uint8_t kDomain[] = {'A','Z','T','1','-','C','H','A','I','N','-','V','1'};
  hmsg.insert(hmsg.end(), kDomain, kDomain + sizeof(kDomain));
  if (sc.seq > 1) hmsg.insert(hmsg.end(), sc.v_prev, sc.v_prev + 32);
  hmsg.insert(hmsg.end(), core.begin(), core.end());

  uint8_t v_new[32];
  if (!sha256_bytes(hmsg.data(), hmsg.size(), v_new)) return false;

  rec_out.reserve(core.size() + tag_len + 32);
  rec_out.insert(rec_out.end(), core.begin(), core.end());
  rec_out.insert(rec_out.end(), v_new, v_new + 32);

  memcpy(sc.v_prev, v_new, 32);
  if (out_v_new) memcpy(out_v_new, v_new, 32);
  return true;
}

void encode_telemetry_snapshot_body_v1(const TelemetrySnapshotV1& t, std::vector<uint8_t>& out) {
  out.clear();
  out.reserve(11);
  out.push_back(1);  // version
  append_u16_be(out, t.window_blocks);
  append_u16_be(out, t.rb_level_min);
  append_u16_be(out, t.rb_level_max);
  append_u16_be(out, t.rb_level_avg_q8);
  append_u16_be(out, t.rb_level_last);
}

bool encrypt_audio_chunk_and_chain(StreamCtx& sc,
                                   const uint8_t* pcm,
                                   size_t pcm_len,
                                   std::vector<uint8_t>& rec_out,
                                   uint8_t out_v_new[32]) {
  return encrypt_payload_and_chain(sc,
                                   kBlockTypePcmAudio,
                                   pcm,
                                   pcm_len,
                                   true,
                                   rec_out,
                                   out_v_new);
}

bool encrypt_signature_block_and_chain(StreamCtx& sc,
                                       uint32_t ref_seq,
                                       const uint8_t sig64[64],
                                       std::vector<uint8_t>& rec_out) {
  uint8_t payload[4 + 64];
  payload[0] = static_cast<uint8_t>((ref_seq >> 24) & 0xFF);
  payload[1] = static_cast<uint8_t>((ref_seq >> 16) & 0xFF);
  payload[2] = static_cast<uint8_t>((ref_seq >> 8) & 0xFF);
  payload[3] = static_cast<uint8_t>(ref_seq & 0xFF);
  memcpy(payload + 4, sig64, 64);
  return encrypt_payload_and_chain(sc,
                                   kBlockTypeSignature,
                                   payload,
                                   sizeof(payload),
                                   false,
                                   rec_out,
                                   nullptr);
}

bool encrypt_dropped_frames_block_and_chain(StreamCtx& sc,
                                            uint16_t missed_frames,
                                            std::vector<uint8_t>& rec_out) {
  uint8_t payload[2];
  payload[0] = static_cast<uint8_t>((missed_frames >> 8) & 0xFF);
  payload[1] = static_cast<uint8_t>(missed_frames & 0xFF);
  return encrypt_payload_and_chain(sc,
                                   kBlockTypeDroppedFrames,
                                   payload,
                                   sizeof(payload),
                                   false,
                                   rec_out,
                                   nullptr);
}

bool encrypt_telemetry_snapshot_block_and_chain(StreamCtx& sc,
                                                const TelemetrySnapshotV1& t,
                                                std::vector<uint8_t>& rec_out) {
  std::vector<uint8_t> body;
  encode_telemetry_snapshot_body_v1(t, body);

  return encrypt_payload_and_chain(sc,
                                   kBlockTypeTelemetrySnapshot,
                                   body.data(),
                                   body.size(),
                                   true,
                                   rec_out,
                                   nullptr);
}

}  // namespace azt
