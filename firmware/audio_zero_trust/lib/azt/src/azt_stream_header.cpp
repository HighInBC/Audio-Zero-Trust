#include "azt_stream_header.h"

#include <Arduino.h>
#include <esp_system.h>
#include <sodium.h>

#include "azt_crypto.h"

namespace azt {

bool build_header_prefix(StreamCtx& sc,
                         const AppState& state,
                         const unsigned char sign_sk[64],
                         uint32_t sig_checkpoint_min_interval,
                         float recommended_decode_gain,
                         const String& recording_started_utc,
                         const String& stream_auth_nonce,
                         uint32_t time_sync_staleness_seconds,
                         float audio_frame_duration_ms,
                         std::vector<uint8_t>& out_prefix) {
  out_prefix.clear();
  esp_fill_random(sc.audio_key, sizeof(sc.audio_key));
  esp_fill_random(sc.nonce_prefix, sizeof(sc.nonce_prefix));
  esp_fill_random(sc.chain_key, sizeof(sc.chain_key));
  memset(sc.chain_genesis_secret, 0, sizeof(sc.chain_genesis_secret));
  memset(sc.v_prev, 0, sizeof(sc.v_prev));
  sc.seq = 0;

  {
    crypto_auth_hmacsha256_state gs;
    crypto_auth_hmacsha256_init(&gs, sc.chain_key, sizeof(sc.chain_key));
    static const uint8_t kGenesisDomain[] = {'A','Z','T','1','-','G','E','N','E','S','I','S','-','V','1'};
    crypto_auth_hmacsha256_update(&gs, kGenesisDomain, sizeof(kGenesisDomain));
    crypto_auth_hmacsha256_final(&gs, sc.chain_genesis_secret);
  }

  String dec_header = "{";
  dec_header += "\"audio_cipher\":\"aes-256-gcm-mixed-blocks-sha256-chain\",";
  dec_header += "\"audio_key_b64\":\"" + b64(sc.audio_key, sizeof(sc.audio_key)) + "\",";
  dec_header += "\"audio_nonce_prefix_b64\":\"" + b64(sc.nonce_prefix, sizeof(sc.nonce_prefix)) + "\",";
  dec_header += "\"audio_tag_len\":16,";
  dec_header += "\"audio_aad_mode\":\"none\",";
  dec_header += "\"audio_format\":\"pcm_s16le\",";
  dec_header += "\"sample_rate_hz\":" + String(state.audio_sample_rate_hz) + ",";
  dec_header += "\"channels\":" + String(state.audio_channels) + ",";
  dec_header += "\"sample_width_bytes\":" + String(state.audio_sample_width_bytes) + ",";
  dec_header += "\"audio_input_source\":\"" + state.audio_input_source + "\",";
  if (state.audio_input_source == "echo_base") {
    dec_header += "\"audio_preamp_gain\":" + String(state.audio_preamp_gain) + ",";
    dec_header += "\"audio_adc_gain\":" + String(state.audio_adc_gain) + ",";
  }
  dec_header += "\"recommended_decode_gain\":" + String(recommended_decode_gain, 3) + ",";
  dec_header += "\"audio_frame_duration_ms\":" + String(audio_frame_duration_ms, 3) + ",";
  dec_header += "\"packetization\":\"none\",";
  dec_header += "\"payload_block_types\":{\"0\":\"pcm_audio\",\"1\":\"ed25519_checkpoint_signature\",\"2\":\"dropped_frames_notice\",\"3\":\"telemetry_snapshot\"},";
  dec_header += "\"encrypted_block_types\":[0,3],";
  dec_header += "\"plaintext_block_types\":[1,2],";
  dec_header += "\"signature_checkpoint_alg\":\"ed25519\",";
  dec_header += "\"signature_checkpoint_domain\":\"AZT1SIG1||ref_seq_u32be||chain_v32 (ref_seq>0) ; AZT1SIG0||chain_genesis_secret32 (ref_seq=0)\",";
  dec_header += "\"chain_genesis_secret_b64\":\"" + b64(sc.chain_genesis_secret, sizeof(sc.chain_genesis_secret)) + "\",";
  dec_header += "\"block1_must_be_signature_ref_seq0\":true,";
  dec_header += "\"signature_checkpoint_min_interval\":" + String(sig_checkpoint_min_interval) + ",";
  dec_header += "\"device_sign_public_key_b64\":\"" + state.device_sign_public_key_b64 + "\",";
  dec_header += "\"device_sign_fingerprint_hex\":\"" + state.device_sign_fingerprint_hex + "\",";
  dec_header += "\"device_chip_id_hex\":\"" + state.device_chip_id_hex + "\",";
  dec_header += "\"chain_alg\":\"hmac-sha256-link\",";
  dec_header += "\"chain_domain\":\"AZT1-CHAIN-V2\",";
  dec_header += "\"chain_key_b64\":\"" + b64(sc.chain_key, sizeof(sc.chain_key)) + "\",";
  dec_header += "\"chain_root_mode\":\"genesis-signature-block\",";
  dec_header += "\"chunk_record_format\":\"seq_u32be|block_type_u8|body_len_u32be|tag_len_u8|body|tag|chain_v32\",";
  dec_header += "\"signature_block_body_format\":\"ref_seq_u32be|sig_ed25519_64\",";
  dec_header += "\"dropped_frames_block_body_format\":\"missed_frames_u16be\",";
  dec_header += "\"telemetry_block_body_format\":\"ver_u8|window_blocks_u16be|rb_level_min_u16be|rb_level_max_u16be|rb_level_avg_q8_u16be|rb_level_last_u16be\",";
  dec_header += "\"telemetry_interval_blocks\":50,";
  dec_header += "\"chain_verify_procedure\":[";
  dec_header += "\"For each chunk record read seq_u32be, block_type_u8, body_len_u32be, tag_len_u8, body, tag, chain_v32.\",";
  dec_header += "\"Let CORE = seq_u32be||block_type_u8||body_len_u32be||tag_len_u8||body||tag.\",";
  dec_header += "\"If seq==1: V_calc = HMAC_SHA256(chain_key, \\\"AZT1-CHAIN-V2\\\"||CORE).\",";
  dec_header += "\"If seq>1: V_calc = HMAC_SHA256(chain_key, \\\"AZT1-CHAIN-V2\\\"||V_prev||CORE).\",";
  dec_header += "\"Require V_calc == chain_v32; then set V_prev = chain_v32.\",";
  dec_header += "\"For block_type in [0,3], derive nonce as audio_nonce_prefix_b64 (4 bytes) || seq_u32be || 0x00000000 and AES-GCM decrypt body||tag with aad=none. For block_type in [1,2], body is plaintext and tag_len must be 0.\"";
  dec_header += "],";
  dec_header += "\"chain_notes\":[";
  dec_header += "\"If verification fails at chunk N, trust only chunks before N.\",";
  dec_header += "\"EOF marker is not required: truncation is expected for live capture files.\",";
  dec_header += "\"Read until end-of-file and accept data up to the last complete chunk record; ignore trailing partial bytes.\",";
  dec_header += "\"Do not parse packet lengths from ciphertext; parse record framing first, then decrypt chunk payload.\"";
  dec_header += "],";
  dec_header += "\"decoder_notes\":[";
  dec_header += "\"PCM samples are raw I2S capture and are not gain-adjusted in firmware.\",";
  dec_header += "\"If desired for monitoring/export loudness, apply recommended_decode_gain during decode/render only.\",";
  dec_header += "\"This stream is chunk-record based. Verify chain_alg on every record before trusting bytes.\",";
  dec_header += "\"block_type is in plaintext framing. block_type 0x00 and 0x03 bodies are AES-GCM encrypted.\",";
  dec_header += "\"block_type 0x01 and 0x02 bodies are plaintext by design for zero-knowledge verification and duration estimation.\",";
  dec_header += "\"block_type 0x01 means checkpoint signature block; body format is ref_seq_u32be|sig_ed25519_64.\",";
  dec_header += "\"To verify block_type 0x01 signature: if ref_seq==0 then message = AZT1SIG0||chain_genesis_secret32; else message = AZT1SIG1||ref_seq_u32be||chain_v32(ref_seq). Verify with device_sign_public_key_b64 using signature_checkpoint_alg.\",";
  dec_header += "\"Block seq=1 MUST be a signature block with ref_seq=0, anchoring the stream to encrypted chain_genesis_secret32.\",";
  dec_header += "\"A valid checkpoint signature means all records up to ref_seq are authenticated by device signing key; chain verification still applies to all records.\",";
  dec_header += "\"block_type 0x02 is dropped frame notice; block_body is missed_frames_u16be and means that many PCM frames were intentionally skipped due to network backpressure.\",";
  dec_header += "\"block_type 0x03 is telemetry snapshot; use telemetry_block_body_format to parse ring-buffer occupancy stats.\",";
  dec_header += "\"Untrusted listeners estimate frames as COUNT(block_type=0) + SUM_DROPPED(block_type=2), then multiply by audio_frame_duration_ms.\"";
  dec_header += "]";
  dec_header += "}";

  uint8_t header_key[32];
  uint8_t header_nonce[12];
  uint8_t header_tag[16];
  esp_fill_random(header_key, sizeof(header_key));
  esp_fill_random(header_nonce, sizeof(header_nonce));

  std::vector<uint8_t> header_ct;
  const uint8_t* dec_header_bytes = reinterpret_cast<const uint8_t*>(dec_header.c_str());
  size_t dec_header_len = dec_header.length();
  uint8_t dec_header_sha256[32];
  if (!sha256_bytes(dec_header_bytes, dec_header_len, dec_header_sha256)) {
    return false;
  }
  if (!aes256_gcm_encrypt(header_key, header_nonce, dec_header_bytes, dec_header_len, header_ct, header_tag)) {
    return false;
  }

  std::vector<uint8_t> wrapped_header_key;
  std::vector<uint8_t> pub(reinterpret_cast<const uint8_t*>(state.listener_pubkey_pem.c_str()),
                           reinterpret_cast<const uint8_t*>(state.listener_pubkey_pem.c_str()) + state.listener_pubkey_pem.length() + 1);
  if (!rsa_oaep_sha256_encrypt_pub(pub.data(), pub.size(), header_key, sizeof(header_key), wrapped_header_key)) {
    return false;
  }

  uint8_t enc_header_sha256[32];
  if (!sha256_bytes(header_ct.data(), header_ct.size(), enc_header_sha256)) {
    return false;
  }

  String plain_header = "{";
  plain_header += "\"version\":0,";
  plain_header += "\"container_major\":0,";
  plain_header += "\"container_minor\":0,";
  plain_header += "\"next_header_key_wrap\":\"rsa-oaep-sha256\",";
  plain_header += "\"next_header_cipher\":\"aes-256-gcm\",";
  plain_header += "\"next_header_wrapped_key_b64\":\"" + b64(wrapped_header_key.data(), wrapped_header_key.size()) + "\",";
  plain_header += "\"next_header_nonce_b64\":\"" + b64(header_nonce, sizeof(header_nonce)) + "\",";
  plain_header += "\"next_header_tag_b64\":\"" + b64(header_tag, sizeof(header_tag)) + "\",";
  plain_header += "\"next_header_aad_mode\":\"none\",";
  plain_header += "\"next_header_recipient_key_fingerprint_alg\":\"sha256-spki-der\",";
  plain_header += "\"next_header_recipient_key_fingerprint_hex\":\"" + state.listener_fingerprint_hex + "\",";
  plain_header += "\"next_header_ciphertext_hash_alg\":\"sha256\",";
  plain_header += "\"next_header_plaintext_hash_alg\":\"sha256\",";
  plain_header += "\"next_header_plaintext_sha256_b64\":\"" + b64(dec_header_sha256, sizeof(dec_header_sha256)) + "\",";
  plain_header += "\"this_header_signature_alg\":\"ed25519\",";
  plain_header += "\"this_header_signature_domain\":\"this_header_json_utf8\",";
  plain_header += "\"this_header_signing_key_fingerprint_alg\":\"sha256-raw-ed25519-pub\",";
  plain_header += "\"this_header_signing_key_fingerprint_hex\":\"" + state.device_sign_fingerprint_hex + "\",";
  plain_header += "\"this_header_signing_key_b64\":\"" + state.device_sign_public_key_b64 + "\",";
  plain_header += "\"device_chip_id_hex\":\"" + state.device_chip_id_hex + "\",";
  if (state.device_certificate_serial.length() > 0) {
    plain_header += "\"device_certificate_serial\":\"" + state.device_certificate_serial + "\",";
  }
  if (state.device_certificate_json.length() > 0) {
    plain_header += "\"device_certificate\":" + state.device_certificate_json + ",";
  }
  if (state.stream_header_auto_record) {
    plain_header += "\"stream_header_auto_record\":true,";
  }
  if (state.stream_header_auto_decode) {
    plain_header += "\"stream_header_auto_decode\":true,";
  }
  plain_header += "\"certificate_verification_procedure\":[";
  plain_header += "\"If device_certificate is present, parse certificate_payload_b64 and signature_b64.\",";
  plain_header += "\"Verify certificate signature with trusted admin signing key using certificate.signature_algorithm.\",";
  plain_header += "\"Require certificate payload device_sign_public_key_b64 to equal next-header device_sign_public_key_b64.\",";
  plain_header += "\"Require certificate payload device_sign_fingerprint_hex to equal next-header device_sign_fingerprint_hex.\",";
  plain_header += "\"Require certificate payload device_chip_id_hex to equal outer header device_chip_id_hex.\",";
  plain_header += "\"If stream_header_auto_record/stream_header_auto_decode are present, treat them as per-recording grants that must be combined with certificate authorized_consumers (logical AND).\",";
  plain_header += "\"If device_certificate_serial is present in outer header, require it equals certificate payload certificate_serial.\"";
  plain_header += "],";
  plain_header += "\"next_header_ciphertext_sha256_b64\":\"" + b64(enc_header_sha256, sizeof(enc_header_sha256)) + "\",";
  plain_header += "\"next_header_ciphertext_len\":" + String(static_cast<unsigned>(header_ct.size())) + ",";
  plain_header += "\"chunk_record_format\":\"seq_u32be|block_type_u8|body_len_u32be|tag_len_u8|body|tag|chain_v32\",";
  plain_header += "\"chain_alg\":\"hmac-sha256-link\",";
  plain_header += "\"chain_domain\":\"AZT1-CHAIN-V2\",";
  plain_header += "\"chain_root_mode\":\"genesis-signature-block\",";
  plain_header += "\"chain_record_bytes_format\":\"seq_u32be|block_type_u8|body_len_u32be|tag_len_u8|body|tag\",";
  plain_header += "\"chain_excludes_field\":\"chain_v32\",";
  plain_header += "\"chain_link_formula\":[";
  plain_header += "\"For seq==1: chain_v32 = HMAC_SHA256(chain_key, chain_domain_bytes || record_bytes).\",";
  plain_header += "\"For seq>1: chain_v32 = HMAC_SHA256(chain_key, chain_domain_bytes || prev_chain_v32 || record_bytes).\"";
  plain_header += "],";
  plain_header += "\"encrypted_block_types\":[0,3],";
  plain_header += "\"plaintext_block_types\":[1,2],";
  plain_header += "\"block_type_map\":{\"0\":\"pcm_audio\",\"1\":\"ed25519_checkpoint_signature\",\"2\":\"dropped_frames_notice\",\"3\":\"telemetry_snapshot\"},";
  plain_header += "\"signature_block_body_format\":\"ref_seq_u32be|sig_ed25519_64\",";
  plain_header += "\"dropped_frames_block_body_format\":\"missed_frames_u16be\",";
  plain_header += "\"signature_checkpoint_alg\":\"ed25519\",";
  plain_header += "\"signature_checkpoint_domain\":\"AZT1SIG1||ref_seq_u32be||chain_v32 (ref_seq>0) ; AZT1SIG0||chain_genesis_secret32 (ref_seq=0)\",";
  plain_header += "\"block1_must_be_signature_ref_seq0\":true,";
  plain_header += "\"signature_verification_procedure\":[";
  plain_header += "\"For block_type=1 parse body as ref_seq_u32be|sig_ed25519_64.\",";
  plain_header += "\"Require block seq=1 to be block_type=1 with ref_seq=0.\",";
  plain_header += "\"If ref_seq==0, build message bytes as AZT1SIG0||chain_genesis_secret32 from decrypted inner header.\",";
  plain_header += "\"If ref_seq>0, find chain_v32(ref_seq) from prior records by sequence number and build message bytes as AZT1SIG1||ref_seq_u32be||chain_v32(ref_seq).\",";
  plain_header += "\"Verify Ed25519 signature with trusted device signing public key selected by this_header_signing_key_fingerprint_hex.\"";
  plain_header += "],";
  plain_header += "\"pcm_blocks_are_single_frame\":true,";
  plain_header += "\"recording_started_utc\":";
  if (recording_started_utc.length() > 0) {
    plain_header += "\"" + recording_started_utc + "\",";
  } else {
    plain_header += "null,";
  }
  plain_header += "\"stream_auth_nonce\":\"" + stream_auth_nonce + "\",";
  plain_header += "\"time_sync_staleness_seconds\":" + String(time_sync_staleness_seconds) + ",";
  plain_header += "\"audio_frame_duration_ms\":" + String(audio_frame_duration_ms, 3) + ",";
  plain_header += "\"audio_input_source\":\"" + state.audio_input_source + "\",";
  if (state.audio_input_source == "echo_base") {
    plain_header += "\"audio_preamp_gain\":" + String(state.audio_preamp_gain) + ",";
    plain_header += "\"audio_adc_gain\":" + String(state.audio_adc_gain) + ",";
  }
  plain_header += "\"estimated_frames_formula\":\"COUNT(block_type=0) + SUM(block_type=2.missed_frames_u16be)\",";
  plain_header += "\"estimated_duration_ms_formula\":\"(COUNT(block_type=0) + SUM(block_type=2.missed_frames_u16be)) * audio_frame_duration_ms\",";
  plain_header += "\"next_header_decrypt_procedure\":[";
  plain_header += "\"base64_decode next_header_wrapped_key_b64 -> next_header_wrapped_key\",";
  plain_header += "\"rsa_oaep_sha256_unwrap input=next_header_wrapped_key -> next_header_key\",";
  plain_header += "\"base64_decode next_header_nonce_b64 -> next_header_nonce\",";
  plain_header += "\"base64_decode next_header_tag_b64 -> next_header_tag\",";
  plain_header += "\"aes_256_gcm_decrypt key=next_header_key nonce=next_header_nonce tag=next_header_tag ciphertext=next_header_ciphertext aad=none -> decrypted_header_json_utf8\"";
  plain_header += "],";
  plain_header += "\"notes\":[";
  plain_header += "\"Read next line after this JSON as base64 this-header signature, then read 2-byte big-endian next-header length N.\",";
  plain_header += "\"If N != 0xFFFF: next header is encrypted/ciphertext and exactly N raw bytes follow.\",";
  plain_header += "\"If N == 0xFFFF: next header is decrypted plaintext JSON (UTF-8) and is newline-terminated (read until LF / 0x0A).\",";
  plain_header += "\"Chunk stream checkpoint signatures use the same signing algorithm/key family as this_header_signature_alg and are selected via this_header_signing_key_fingerprint_hex trust lookup.\",";
  plain_header += "\"Special rule: block seq=1 MUST be a signature block whose ref_seq=0. This block signs encrypted-only chain_genesis_secret32 and cannot be re-signed without inner-header decryption.\",";
  plain_header += "\"Use RSA private key to recover/decrypt encrypted header metadata when N != 0xFFFF.\",";
  plain_header += "\"Remaining bytes are chunk records: seq_u32be|block_type_u8|body_len_u32be|tag_len_u8|body|tag|chain_v32.\",";
  plain_header += "\"Silently discard trailing partial/incomplete chunk records at end-of-file.\",";
  plain_header += "\"If unsigned tail blocks exist after the last verified checkpoint, warn the user that end-of-audio content is unsigned and may be tampered.\"";
  plain_header += "]";
  plain_header += "}";

  unsigned char hdr_sig[crypto_sign_ed25519_BYTES] = {0};
  unsigned long long hdr_sig_len = 0;
  std::vector<uint8_t> sig_msg;
  sig_msg.reserve(plain_header.length());
  sig_msg.insert(sig_msg.end(), plain_header.begin(), plain_header.end());
  if (crypto_sign_ed25519_detached(hdr_sig, &hdr_sig_len, sig_msg.data(), sig_msg.size(), sign_sk) != 0 ||
      hdr_sig_len != crypto_sign_ed25519_BYTES) {
    return false;
  }
  String sig_line = b64(hdr_sig, crypto_sign_ed25519_BYTES) + "\n";

  String magic = "AZT1\n";
  String p1 = plain_header + "\n";

  out_prefix.reserve(magic.length() + p1.length() + sig_line.length() + 2 + header_ct.size());
  out_prefix.insert(out_prefix.end(), magic.begin(), magic.end());
  out_prefix.insert(out_prefix.end(), p1.begin(), p1.end());
  out_prefix.insert(out_prefix.end(), sig_line.begin(), sig_line.end());
  if (header_ct.size() > 0xFFFF) return false;
  append_u16_be(out_prefix, static_cast<uint16_t>(header_ct.size()));
  out_prefix.insert(out_prefix.end(), header_ct.begin(), header_ct.end());
  return true;
}

}  // namespace azt
