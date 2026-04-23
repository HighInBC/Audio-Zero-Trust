#include "azt_stream.h"

#include <Arduino.h>
#include <algorithm>
#include <cmath>
#include <Preferences.h>
#include <esp_system.h>
#include <esp_timer.h>
#include <mbedtls/base64.h>
#include <sodium.h>
#include <time.h>

#include "azt_audio_ring.h"
#include "azt_constants.h"
#include "azt_crypto.h"
#include "azt_device_io.h"
#include "azt_kv_store.h"
#include "azt_stream_header.h"
#include "azt_stream_record.h"
#include "azt_stream_signer.h"

namespace azt {

#if CONFIG_IDF_TARGET_ESP32S3
static constexpr float kRecommendedDecodeGain = 1.0f;
#else
static constexpr float kRecommendedDecodeGain = 4.0f;
#endif
static constexpr uint32_t kSigCheckpointMinInterval = 10;
static constexpr uint32_t kSigCheckpointMaxInterval = 160;
static constexpr uint32_t kTelemetryIntervalBlocks = 50;
static constexpr uint32_t kMaxContiguousDropMs = 10000;
static volatile bool g_stream_shutdown_requested = false;
static String g_stream_shutdown_source = "unspecified";

// Active stream session + optional terminate request keyed by initiating nonce.
static String g_active_stream_nonce = "";
static String g_pending_terminate_nonce = "";
static String g_pending_terminate_text = "";
static uint8_t g_pending_terminate_reason_code = 0;
static volatile bool g_pending_terminate = false;

static constexpr uint8_t kCloseReasonNormalEnd = 0x00;
static constexpr uint8_t kCloseReasonAudioDegradedReinit = 0x01;
static constexpr uint8_t kCloseReasonRequestedShutdown = 0x02;

static String make_close_reason_json(const char* cause) {
  String out = "{\"cause\":\"";
  out += String(cause ? cause : "unknown");
  out += "\"}";
  return out;
}

static String make_close_reason_json_with_meta(const char* cause,
                                               const char* initiator,
                                               const char* trigger) {
  String out = "{\"cause\":\"";
  out += String(cause ? cause : "unknown");
  out += "\",\"initiator\":\"";
  out += String(initiator ? initiator : "system");
  out += "\",\"trigger\":\"";
  out += String(trigger ? trigger : "unknown");
  out += "\"}";
  return out;
}

void request_stream_shutdown(const char* source) {
  g_stream_shutdown_requested = true;
  g_stream_shutdown_source = String(source ? source : "unspecified");
  Serial.printf("AZT_STREAM_SHUTDOWN_REQUEST source=%s\n", g_stream_shutdown_source.c_str());
}
void clear_stream_shutdown_request() {
  g_stream_shutdown_requested = false;
  g_stream_shutdown_source = "unspecified";
}

void set_active_stream_session_nonce(const String& nonce) {
  g_active_stream_nonce = nonce;
}

void clear_active_stream_session_nonce(const String& nonce) {
  if (nonce.length() == 0 || g_active_stream_nonce == nonce) {
    g_active_stream_nonce = "";
  }
  if (g_pending_terminate && (nonce.length() == 0 || g_pending_terminate_nonce == nonce)) {
    g_pending_terminate = false;
    g_pending_terminate_nonce = "";
    g_pending_terminate_text = "";
    g_pending_terminate_reason_code = 0;
  }
}

bool request_stream_termination_by_nonce(const String& nonce,
                                         uint8_t reason_code,
                                         const String& reason_text) {
  if (nonce.length() == 0 || g_active_stream_nonce.length() == 0 || nonce != g_active_stream_nonce) {
    return false;
  }
  g_pending_terminate_nonce = nonce;
  g_pending_terminate_reason_code = reason_code;
  g_pending_terminate_text = reason_text;
  g_pending_terminate = true;
  return true;
}

bool consume_stream_termination_for_nonce(const String& nonce,
                                          uint8_t& out_reason_code,
                                          String& out_reason_text) {
  if (!g_pending_terminate || nonce.length() == 0 || nonce != g_pending_terminate_nonce) {
    return false;
  }
  out_reason_code = g_pending_terminate_reason_code;
  out_reason_text = g_pending_terminate_text;
  g_pending_terminate = false;
  g_pending_terminate_nonce = "";
  g_pending_terminate_text = "";
  g_pending_terminate_reason_code = 0;
  return true;
}

static bool emit_stream_close_and_finalize(WiFiClient& client,
                                           StreamCtx& sc,
                                           const unsigned char sign_sk[crypto_sign_ed25519_SECRETKEYBYTES],
                                           uint8_t reason_code,
                                           const String& reason_text,
                                           std::vector<uint8_t>& rec) {
  const char* txt = reason_text.c_str();
  if (!encrypt_message_block_and_chain(sc,
                                       reason_code,
                                       reinterpret_cast<const uint8_t*>(txt),
                                       strlen(txt),
                                       rec) ||
      !send_chunked(client, rec.data(), rec.size())) {
    return false;
  }

  const uint32_t ref_seq = sc.seq;
  unsigned char sig[crypto_sign_ed25519_BYTES] = {0};
  unsigned long long sig_len = 0;
  uint8_t msg[8 + 4 + 32];
  memcpy(msg, "AZT1SIG1", 8);
  msg[8] = static_cast<uint8_t>((ref_seq >> 24) & 0xFF);
  msg[9] = static_cast<uint8_t>((ref_seq >> 16) & 0xFF);
  msg[10] = static_cast<uint8_t>((ref_seq >> 8) & 0xFF);
  msg[11] = static_cast<uint8_t>(ref_seq & 0xFF);
  memcpy(msg + 12, sc.v_prev, 32);

  if (crypto_sign_ed25519_detached(sig, &sig_len, msg, sizeof(msg), sign_sk) != 0 ||
      sig_len != crypto_sign_ed25519_BYTES) {
    return false;
  }

  return encrypt_finalize_block_and_chain(sc, ref_seq, sig, rec) &&
         send_chunked(client, rec.data(), rec.size());
}

int parse_seconds_from_path(const String& path) {
  int q = path.indexOf('?');
  if (q < 0) return 0;
  String query = path.substring(q + 1);
  int k = query.indexOf("seconds=");
  if (k < 0) return 0;
  int start = k + 8;
  int end = query.indexOf('&', start);
  String v = (end < 0) ? query.substring(start) : query.substring(start, end);
  int parsed = v.toInt();
  if (parsed <= 0) return 0;
  if (parsed > 86400) parsed = 86400;
  return parsed;
}

bool parse_signbench_from_path(const String& path) {
  int q = path.indexOf('?');
  if (q < 0) return false;
  String query = path.substring(q + 1);
  int k = query.indexOf("sigbench=");
  if (k < 0) return false;
  int start = k + 9;
  int end = query.indexOf('&', start);
  String v = (end < 0) ? query.substring(start) : query.substring(start, end);
  v.toLowerCase();
  return v == "1" || v == "true" || v == "yes" || v == "on";
}

int parse_drop_test_frames_from_path(const String& path) {
  int q = path.indexOf('?');
  if (q < 0) return 0;
  String query = path.substring(q + 1);
  int k = query.indexOf("drop_test_frames=");
  if (k < 0) return 0;
  int start = k + 17;
  int end = query.indexOf('&', start);
  String v = (end < 0) ? query.substring(start) : query.substring(start, end);
  int parsed = v.toInt();
  if (parsed <= 0) return 0;
  if (parsed > 65535) parsed = 65535;
  return parsed;
}

uint32_t max_contiguous_drop_frames_for_config(uint32_t frame_samples,
                                               uint32_t max_contiguous_drop_ms,
                                               uint32_t sample_rate_hz) {
  if (frame_samples == 0 || sample_rate_hz == 0) return 1;
  uint32_t frames = (max_contiguous_drop_ms * sample_rate_hz) / (1000U * frame_samples);
  return std::max<uint32_t>(1, frames);
}

bool should_disconnect_for_contiguous_drop(uint32_t contiguous_drop_frames,
                                           uint32_t frame_samples,
                                           uint32_t max_contiguous_drop_ms,
                                           uint32_t sample_rate_hz) {
  return contiguous_drop_frames >=
         max_contiguous_drop_frames_for_config(frame_samples, max_contiguous_drop_ms, sample_rate_hz);
}

void account_drop_event(uint32_t drop_frames,
                        uint32_t& pending_dropped_frames,
                        uint64_t& dropped_frames_total,
                        uint32_t& contiguous_drop_frames) {
  pending_dropped_frames += drop_frames;
  dropped_frames_total += drop_frames;
  contiguous_drop_frames += drop_frames;
}

bool apply_drop_and_check_stall(uint32_t drop_frames,
                                uint32_t frame_samples,
                                uint32_t& pending_dropped_frames,
                                uint64_t& dropped_frames_total,
                                uint32_t& contiguous_drop_frames,
                                uint32_t max_contiguous_drop_ms,
                                uint32_t sample_rate_hz) {
  account_drop_event(drop_frames, pending_dropped_frames, dropped_frames_total, contiguous_drop_frames);
  return should_disconnect_for_contiguous_drop(contiguous_drop_frames,
                                               frame_samples,
                                               max_contiguous_drop_ms,
                                               sample_rate_hz);
}

StreamLoopDecision evaluate_stream_loop_branch(bool had_ingress_drop,
                                               bool drop_test_active,
                                               bool low_write_capacity,
                                               bool send_failed,
                                               uint32_t contiguous_drop_frames,
                                               uint32_t frame_samples,
                                               uint32_t max_contiguous_drop_ms,
                                               uint32_t sample_rate_hz) {
  StreamLoopDecision d{};
  d.emit_drop_notice = had_ingress_drop;

  if (drop_test_active || low_write_capacity || send_failed) {
    d.skip_audio_send = true;
  }

  d.disconnect_for_stall = should_disconnect_for_contiguous_drop(contiguous_drop_frames,
                                                                 frame_samples,
                                                                 max_contiguous_drop_ms,
                                                                 sample_rate_hz);
  return d;
}

bool should_defer_drop_notice_for_backpressure(int available_for_write,
                                               int min_notice_write) {
  return available_for_write > 0 && available_for_write < min_notice_write;
}

bool is_low_write_capacity(int available_for_write, int min_audio_write) {
  return available_for_write > 0 && available_for_write < min_audio_write;
}

uint32_t sig_checkpoint_interval_on_missed_response(uint32_t current,
                                                    uint32_t min_interval,
                                                    uint32_t max_interval) {
  uint32_t bounded = std::max<uint32_t>(min_interval, current);
  if (bounded >= max_interval) return max_interval;
  return std::min<uint32_t>(max_interval, bounded * 2);
}

uint32_t sig_checkpoint_interval_on_response(uint32_t current, uint32_t min_interval) {
  uint32_t bounded = std::max<uint32_t>(min_interval, current);
  return std::max<uint32_t>(min_interval, bounded / 2);
}

void telemetry_accumulate_level(TelemetryAccumulator& acc, uint16_t rb_level) {
  acc.level_last = rb_level;
  if (rb_level < acc.level_min) acc.level_min = rb_level;
  if (rb_level > acc.level_max) acc.level_max = rb_level;
  acc.level_sum += rb_level;
  acc.samples++;
}

bool telemetry_window_ready(const TelemetryAccumulator& acc, uint32_t interval_blocks) {
  return acc.samples >= interval_blocks;
}

TelemetrySnapshotV1 telemetry_snapshot_from_acc(const TelemetryAccumulator& acc) {
  TelemetrySnapshotV1 t{};
  t.window_blocks = static_cast<uint16_t>(acc.samples);
  t.rb_level_min = (acc.level_min == 0xFFFF) ? 0 : acc.level_min;
  t.rb_level_max = acc.level_max;
  t.rb_level_last = acc.level_last;
  t.rb_level_avg_q8 = (acc.samples == 0)
                          ? 0
                          : static_cast<uint16_t>((acc.level_sum * 256ULL) / acc.samples);
  return t;
}

void telemetry_reset(TelemetryAccumulator& acc) {
  acc.samples = 0;
  acc.level_sum = 0;
  acc.level_min = 0xFFFF;
  acc.level_max = 0;
  acc.level_last = 0;
}

static bool format_utc_iso8601(time_t t, String& out) {
  out = "";
  if (t < 1700000000) return false;
  struct tm tm_utc;
  if (gmtime_r(&t, &tm_utc) == nullptr) return false;
  char buf[32];
  if (strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tm_utc) == 0) return false;
  out = String(buf);
  return true;
}

static bool is_active_certificate_serial(const String& cert_serial) {
  if (cert_serial.length() == 0) return false;
  Preferences p;
  if (!p.begin("aztcfg", true)) return false;
  String stored = kv_get_string(p, "dev_cert_sn", "");
  p.end();
  return stored.length() > 0 && stored == cert_serial;
}

static bool get_active_recorder_auth_state(bool& configured, String& fp_hex) {
  configured = false;
  fp_hex = "";
  Preferences p;
  if (!p.begin("aztcfg", true)) return false;
  String pub = kv_get_string(p, "rec_auth_pub", "");
  String fp = kv_get_string(p, "rec_auth_fp", "");
  p.end();
  configured = pub.length() > 0 && fp.length() == 64;
  fp_hex = fp;
  return true;
}

static bool load_device_sign_sk(unsigned char out_sk[crypto_sign_ed25519_SECRETKEYBYTES]) {
  Preferences p;
  p.begin("aztcfg", true);
  String sk_b64 = kv_get_string(p, "dev_sign_priv", "");
  p.end();
  if (sk_b64.length() == 0) return false;

  size_t olen = 0;
  if (mbedtls_base64_decode(out_sk,
                            crypto_sign_ed25519_SECRETKEYBYTES,
                            &olen,
                            reinterpret_cast<const unsigned char*>(sk_b64.c_str()),
                            sk_b64.length()) != 0) {
    return false;
  }
  return olen == crypto_sign_ed25519_SECRETKEYBYTES;
}

void send_json(WiFiClient& client, int code, const String& body) {
  client.print("HTTP/1.1 ");
  client.print(code);
  client.print(code == 200 ? " OK\r\n" : " Error\r\n");
  client.print("Content-Type: application/json\r\n");
  client.print("Connection: close\r\n");
  client.print("Content-Length: ");
  client.print(body.length());
  client.print("\r\n\r\n");
  client.print(body);
}

static constexpr BaseType_t kStreamPipelineCore = 1;
static constexpr BaseType_t kSignerCore = 0;

static void handle_stream_impl(WiFiClient& client, int seconds, const AppState& state, const String& stream_auth_nonce, bool signbench_each_chunk, bool enable_telemetry, int drop_test_frames) {
  clear_stream_shutdown_request();

  if (!state.signed_config_ready ||
      state.admin_pubkey_pem.length() == 0 || state.admin_fingerprint_hex.length() != 64 ||
      state.listener_pubkey_pem.length() == 0 || state.listener_fingerprint_hex.length() != 64) {
    send_json(client, 403,
              "{\"ok\":false,\"error\":\"ERR_CONFIG_STATE\",\"detail\":\"stream disabled until signed config with admin_key and listener_key is installed\"}");
    return;
  }

  unsigned char sign_sk[crypto_sign_ed25519_SECRETKEYBYTES] = {0};
  bool signbench_enabled = false;

  if (sodium_init() < 0 || !load_device_sign_sk(sign_sk)) {
    send_json(client, 500,
              "{\"ok\":false,\"error\":\"ERR_DEVICE_SIGN_KEY\",\"detail\":\"device signing key unavailable\"}");
    return;
  }

  if (signbench_each_chunk) {
    signbench_enabled = true;
  }

  StreamSigner signer;
  if (!signer.begin(sign_sk, xTaskGetCurrentTaskHandle(), kSignerCore)) {
    send_json(client, 500,
              "{\"ok\":false,\"error\":\"ERR_RUNTIME\",\"detail\":\"failed to start signer task\"}");
    return;
  }

  client.print("HTTP/1.1 200 OK\r\n");
  client.print("Content-Type: application/octet-stream\r\n");
  client.print("Cache-Control: no-store\r\n");
  client.print("Connection: close\r\n");
  client.print("Transfer-Encoding: chunked\r\n\r\n");

  StreamCtx sc{};
  std::vector<uint8_t> prefix;

  String recording_started_utc;
  uint32_t staleness_s = 0;
  {
    time_t now = time(nullptr);
    if (format_utc_iso8601(now, recording_started_utc) && state.time_synced && state.time_last_sync_epoch > 0) {
      if (now >= static_cast<time_t>(state.time_last_sync_epoch)) {
        staleness_s = static_cast<uint32_t>(now - static_cast<time_t>(state.time_last_sync_epoch));
      }
    } else {
      recording_started_utc = "";
      staleness_s = 0;
    }
  }
  const uint32_t sample_rate_hz = state.audio_sample_rate_hz > 0 ? state.audio_sample_rate_hz : constants::audio::kDefaultSampleRateHz;
  const uint32_t channels = state.audio_channels > 0 ? state.audio_channels : static_cast<uint32_t>(constants::audio::kDefaultChannels);
  const uint32_t sample_width_bytes = state.audio_sample_width_bytes > 0 ? state.audio_sample_width_bytes : static_cast<uint32_t>(constants::audio::kDefaultSampleWidthBytes);
  const uint32_t bytes_per_frame_sample = std::max<uint32_t>(1U, channels * sample_width_bytes);
  const uint32_t frame_samples = std::max<uint32_t>(1U, static_cast<uint32_t>(kMicFrameBytes / bytes_per_frame_sample));
  const float audio_frame_duration_ms =
      (1000.0f * static_cast<float>(frame_samples)) / static_cast<float>(sample_rate_hz);

  if (!build_header_prefix(sc,
                           state,
                           sign_sk,
                           kSigCheckpointMinInterval,
                           kRecommendedDecodeGain,
                           recording_started_utc,
                           stream_auth_nonce,
                           staleness_s,
                           audio_frame_duration_ms,
                           prefix)) {
    client.print("0\r\n\r\n");
    client.flush();
    return;
  }
  if (!send_chunked(client, prefix.data(), prefix.size())) {
    client.print("0\r\n\r\n");
    client.flush();
    return;
  }

  MicRing* mic_ring = get_shared_mic_ring();
  if (!mic_ring) {
    signer.stop();
    send_json(client, 500,
              "{\"ok\":false,\"error\":\"ERR_RUNTIME\",\"detail\":\"shared mic ring unavailable\"}");
    return;
  }

  std::vector<uint8_t> rec;
  rec.reserve(4 + 4 + 1 + kMicFrameBytes + 16 + 32);

  {
    unsigned char sig0[crypto_sign_ed25519_BYTES] = {0};
    unsigned long long sig0_len = 0;
    uint8_t msg0[8 + 32];
    memcpy(msg0, "AZT1SIG0", 8);
    memcpy(msg0 + 8, sc.chain_genesis_secret, 32);
    if (crypto_sign_ed25519_detached(sig0, &sig0_len, msg0, sizeof(msg0), sign_sk) != 0 ||
        sig0_len != crypto_sign_ed25519_BYTES ||
        !encrypt_signature_block_and_chain(sc, 0, sig0, rec) ||
        !send_chunked(client, rec.data(), rec.size())) {
      signer.stop();
      client.print("0\r\n\r\n");
      client.flush();
      return;
    }
  }

  set_active_stream_session_nonce(stream_auth_nonce);
  mic_ring_set_stream_active(*mic_ring, true);
  mic_ring_reset_dropped_newest(*mic_ring);

  const bool finite_stream = seconds > 0;
  const uint64_t stream_start_us = static_cast<uint64_t>(esp_timer_get_time());
  const uint64_t deadline = finite_stream
                                ? (stream_start_us + static_cast<uint64_t>(seconds) * 1000000ULL)
                                : 0ULL;

  uint64_t chunks = 0;
  uint64_t process_us = 0;
  uint64_t sign_us = 0;
  uint64_t sig_blocks_sent = 0;
  uint64_t sig_req_dropped = 0;
  uint64_t dropped_frames_total = 0;
  uint64_t dropped_notice_blocks = 0;
  uint64_t telemetry_blocks_sent = 0;
  uint64_t sender_underflows = 0;
  uint32_t pending_dropped_frames = 0;
  uint32_t contiguous_drop_frames = 0;
  bool disconnected_for_stall = false;
  const String started_certificate_serial = state.device_certificate_serial;
  const bool started_with_certificate = started_certificate_serial.length() > 0;
  const bool started_with_recorder_auth = state.recorder_auth_pubkey_b64.length() > 0 && state.recorder_auth_fingerprint_hex.length() == 64;
  const String started_recorder_auth_fp = state.recorder_auth_fingerprint_hex;

  TelemetryAccumulator telem{};
  uint8_t degraded_windows = 0;
  bool trigger_audio_reinit = false;
  uint8_t close_reason_code = kCloseReasonNormalEnd;
  String close_reason_text = make_close_reason_json("normal_end");
  int drop_test_remaining = drop_test_frames;
  uint32_t sig_interval = kSigCheckpointMinInterval;
  uint32_t last_sig_ref_seq = 0;
  bool sig_req_pending = false;

  while (client.connected() && !g_stream_shutdown_requested &&
         (!finite_stream || static_cast<uint64_t>(esp_timer_get_time()) < deadline)) {
    const uint64_t t1 = static_cast<uint64_t>(esp_timer_get_time());

    if (started_with_certificate && !is_active_certificate_serial(started_certificate_serial)) {
      close_reason_code = kCloseReasonRequestedShutdown;
      close_reason_text = make_close_reason_json("certificate_revoked_or_rotated");
      break;
    }

    // Halt active stream if recorder auth key posture changes mid-stream
    // (added/removed/rotated), matching certificate revocation behavior.
    {
      bool current_with_recorder_auth = false;
      String current_recorder_auth_fp;
      if (get_active_recorder_auth_state(current_with_recorder_auth, current_recorder_auth_fp)) {
        if (current_with_recorder_auth != started_with_recorder_auth) {
          close_reason_code = kCloseReasonRequestedShutdown;
          close_reason_text = make_close_reason_json("recorder_auth_posture_changed");
          break;
        }
        if (started_with_recorder_auth && current_recorder_auth_fp != started_recorder_auth_fp) {
          close_reason_code = kCloseReasonRequestedShutdown;
          close_reason_text = make_close_reason_json("recorder_auth_key_rotated");
          break;
        }
      }
    }

    // Recorder/admin can request graceful termination using the initiating stream nonce.
    {
      uint8_t req_reason = 0;
      String req_text;
      if (consume_stream_termination_for_nonce(stream_auth_nonce, req_reason, req_text)) {
        close_reason_code = req_reason;
        close_reason_text = req_text.length() > 0
                                ? req_text
                                : make_close_reason_json_with_meta("requested_termination", "api", "stream_terminate_endpoint");
        break;
      }
    }

    const uint64_t ingress_dropped = mic_ring_take_dropped_newest(*mic_ring);
    if (ingress_dropped > 0) {
      bool stalled = apply_drop_and_check_stall(static_cast<uint32_t>(ingress_dropped), frame_samples, pending_dropped_frames, dropped_frames_total, contiguous_drop_frames, kMaxContiguousDropMs, sample_rate_hz);
      StreamLoopDecision d = evaluate_stream_loop_branch(true, false, false, false, contiguous_drop_frames, frame_samples, kMaxContiguousDropMs, sample_rate_hz);
      if (stalled || d.disconnect_for_stall) {
        disconnected_for_stall = true;
        close_reason_code = kCloseReasonRequestedShutdown;
        close_reason_text = make_close_reason_json("ingress_drop_stall");
        break;
      }
    }

    MicFrame frame;
    if (!mic_ring_pop(*mic_ring, frame)) {
      sender_underflows++;
      vTaskDelay(pdMS_TO_TICKS(1));
      continue;
    }


    if (drop_test_remaining > 0) {
      drop_test_remaining--;
      bool stalled = apply_drop_and_check_stall(1, frame_samples, pending_dropped_frames, dropped_frames_total, contiguous_drop_frames, kMaxContiguousDropMs, sample_rate_hz);
      StreamLoopDecision d = evaluate_stream_loop_branch(false, true, false, false, contiguous_drop_frames, frame_samples, kMaxContiguousDropMs, sample_rate_hz);
      if (stalled || d.disconnect_for_stall) {
        disconnected_for_stall = true;
        close_reason_code = kCloseReasonRequestedShutdown;
        close_reason_text = make_close_reason_json("drop_test_stall");
        break;
      }
      if (d.skip_audio_send) continue;
    }

    while (pending_dropped_frames > 0) {
      int afw_notice = client.availableForWrite();
      if (should_defer_drop_notice_for_backpressure(afw_notice, 64)) break;
      uint16_t emit = static_cast<uint16_t>(std::min<uint32_t>(pending_dropped_frames, 0xFFFF));
      if (!encrypt_dropped_frames_block_and_chain(sc, emit, rec)) break;
      if (!send_chunked(client, rec.data(), rec.size())) break;
      pending_dropped_frames -= emit;
      dropped_notice_blocks++;
    }

    int afw = client.availableForWrite();
    if (is_low_write_capacity(afw, 32)) {
      bool stalled = apply_drop_and_check_stall(1, frame_samples, pending_dropped_frames, dropped_frames_total, contiguous_drop_frames, kMaxContiguousDropMs, sample_rate_hz);
      StreamLoopDecision d = evaluate_stream_loop_branch(false, false, true, false, contiguous_drop_frames, frame_samples, kMaxContiguousDropMs, sample_rate_hz);
      if (stalled || d.disconnect_for_stall) {
        disconnected_for_stall = true;
        close_reason_code = kCloseReasonRequestedShutdown;
        close_reason_text = make_close_reason_json("low_write_capacity_stall");
        break;
      }
      if (d.skip_audio_send) continue;
    }

    uint8_t v_new[32];
    if (!encrypt_audio_chunk_and_chain(sc, frame.data.data(), frame.len, rec, v_new)) {
      close_reason_code = kCloseReasonRequestedShutdown;
      close_reason_text = make_close_reason_json("encrypt_audio_chunk_failed");
      break;
    }

    if (signbench_enabled) {
      unsigned char sig[crypto_sign_ed25519_BYTES] = {0};
      unsigned long long sig_len = 0;
      const uint64_t ts0 = static_cast<uint64_t>(esp_timer_get_time());
      if (crypto_sign_ed25519_detached(sig, &sig_len, rec.data(), rec.size(), sign_sk) != 0 ||
          sig_len != crypto_sign_ed25519_BYTES) {
        close_reason_code = kCloseReasonRequestedShutdown;
        close_reason_text = make_close_reason_json("chunk_signature_failed");
        break;
      }
      const uint64_t ts1 = static_cast<uint64_t>(esp_timer_get_time());
      sign_us += (ts1 - ts0);
    } else {
      const bool due_checkpoint = (sc.seq % sig_interval) == 0;
      if (due_checkpoint) {
        if (sig_req_pending) {
          sig_req_dropped++;
          if (sig_interval < kSigCheckpointMaxInterval) {
            sig_interval = sig_checkpoint_interval_on_missed_response(sig_interval, kSigCheckpointMinInterval, kSigCheckpointMaxInterval);
          }
        }
        signer.submit(sc.seq, v_new);
        sig_req_pending = true;
      }
    }

    if (!send_chunked(client, rec.data(), rec.size())) {
      bool stalled = apply_drop_and_check_stall(1, frame_samples, pending_dropped_frames, dropped_frames_total, contiguous_drop_frames, kMaxContiguousDropMs, sample_rate_hz);
      StreamLoopDecision d = evaluate_stream_loop_branch(false, false, false, true, contiguous_drop_frames, frame_samples, kMaxContiguousDropMs, sample_rate_hz);
      if (stalled || d.disconnect_for_stall) {
        disconnected_for_stall = true;
        close_reason_code = kCloseReasonRequestedShutdown;
        close_reason_text = make_close_reason_json("send_chunk_stall_or_disconnect");
        break;
      }
      if (d.skip_audio_send) continue;
    }
    chunks++;
    contiguous_drop_frames = 0;

    const uint16_t rb_level = static_cast<uint16_t>(mic_ring_count(*mic_ring));
    telemetry_accumulate_level(telem, rb_level);

    if (enable_telemetry && telemetry_window_ready(telem, kTelemetryIntervalBlocks)) {
      TelemetrySnapshotV1 t = telemetry_snapshot_from_acc(telem);

      if (encrypt_telemetry_snapshot_block_and_chain(sc, t, rec) && send_chunked(client, rec.data(), rec.size())) {
        telemetry_blocks_sent++;
      }

      telemetry_reset(telem);
    }

    // Emit ready signature checkpoint blocks (type 0x01).
    SignResponse sr{};
    while (signer.poll(sr)) {
      if (sr.ref_seq <= last_sig_ref_seq) continue;
      if (!encrypt_signature_block_and_chain(sc, sr.ref_seq, sr.sig64, rec)) break;
      if (!send_chunked(client, rec.data(), rec.size())) break;
      sig_blocks_sent++;
      last_sig_ref_seq = sr.ref_seq;
      sig_req_pending = false;
      if (sig_interval > kSigCheckpointMinInterval) {
        sig_interval = sig_checkpoint_interval_on_response(sig_interval, kSigCheckpointMinInterval);
      }
    }

    const uint64_t t2 = static_cast<uint64_t>(esp_timer_get_time());
    process_us += (t2 - t1);
  }

  if (g_stream_shutdown_requested && !trigger_audio_reinit) {
    // Preserve more specific causes set earlier in the loop.
    if (close_reason_code == kCloseReasonNormalEnd) {
      close_reason_code = kCloseReasonRequestedShutdown;
      if (close_reason_text.length() == 0 ||
          close_reason_text == "normal_end" ||
          close_reason_text == make_close_reason_json("normal_end")) {
        close_reason_text = make_close_reason_json_with_meta("stream_shutdown_requested", "system", g_stream_shutdown_source.c_str());
      }
    }
  } else if (finite_stream && close_reason_code == kCloseReasonNormalEnd) {
    close_reason_text = make_close_reason_json("planned_duration_elapsed");
  } else if (!client.connected() && close_reason_code == kCloseReasonNormalEnd) {
    close_reason_code = kCloseReasonRequestedShutdown;
    close_reason_text = make_close_reason_json("client_disconnected");
  }

  while (client.connected() && pending_dropped_frames > 0) {
    uint16_t emit = static_cast<uint16_t>(std::min<uint32_t>(pending_dropped_frames, 0xFFFF));
    if (!encrypt_dropped_frames_block_and_chain(sc, emit, rec)) break;
    if (!send_chunked(client, rec.data(), rec.size())) break;
    pending_dropped_frames -= emit;
    dropped_notice_blocks++;
  }

  if (client.connected()) {
    if (!emit_stream_close_and_finalize(client, sc, sign_sk, close_reason_code, close_reason_text, rec)) {
      Serial.printf("AZT_STREAM_FINALIZE_FAIL reason=%u\n", static_cast<unsigned>(close_reason_code));
    }
  }

  client.print("0\r\n\r\n");
  client.flush();

  signer.stop();

  const uint64_t stream_end_us = static_cast<uint64_t>(esp_timer_get_time());
  const uint64_t total_us = (stream_end_us > stream_start_us) ? (stream_end_us - stream_start_us) : 1;
  const double busy_pct = (100.0 * static_cast<double>(process_us)) / static_cast<double>(total_us);
  MicIngressStats ingress = mic_ring_snapshot_stats(*mic_ring);

  if (signbench_each_chunk) {
    const double sign_pct = (100.0 * static_cast<double>(sign_us)) / static_cast<double>(total_us);
    Serial.printf(
        "AZT_SIGBENCH chunks=%llu total_us=%llu busy_us=%llu busy_pct=%.2f sign_us=%llu sign_pct=%.2f i2s_fail=%llu i2s_empty=%llu dropped_frames=%llu dropped_notice_blocks=%llu telemetry_blocks=%llu sender_underflows=%llu disconnect_stall=%u read_wait_us=%llu rb_high_water=%u\n",
        static_cast<unsigned long long>(chunks),
        static_cast<unsigned long long>(total_us),
        static_cast<unsigned long long>(process_us), busy_pct,
        static_cast<unsigned long long>(sign_us), sign_pct,
        static_cast<unsigned long long>(ingress.i2s_fail),
        static_cast<unsigned long long>(ingress.i2s_empty),
        static_cast<unsigned long long>(dropped_frames_total),
        static_cast<unsigned long long>(dropped_notice_blocks),
        static_cast<unsigned long long>(telemetry_blocks_sent),
        static_cast<unsigned long long>(sender_underflows),
        static_cast<unsigned>(disconnected_for_stall ? 1 : 0),
        static_cast<unsigned long long>(ingress.read_wait_us),
        static_cast<unsigned>(mic_ring->high_water));
  } else {
    Serial.printf(
        "AZT_SIGCP chunks=%llu sig_blocks=%llu sig_req_dropped=%llu dropped_frames=%llu dropped_notice_blocks=%llu telemetry_blocks=%llu sender_underflows=%llu disconnect_stall=%u final_interval=%u busy_pct=%.2f i2s_fail=%llu i2s_empty=%llu rb_high_water=%u\n",
        static_cast<unsigned long long>(chunks),
        static_cast<unsigned long long>(sig_blocks_sent),
        static_cast<unsigned long long>(sig_req_dropped),
        static_cast<unsigned long long>(dropped_frames_total),
        static_cast<unsigned long long>(dropped_notice_blocks),
        static_cast<unsigned long long>(telemetry_blocks_sent),
        static_cast<unsigned long long>(sender_underflows),
        static_cast<unsigned>(disconnected_for_stall ? 1 : 0),
        static_cast<unsigned>(sig_interval),
        busy_pct,
        static_cast<unsigned long long>(ingress.i2s_fail),
        static_cast<unsigned long long>(ingress.i2s_empty),
        static_cast<unsigned>(mic_ring->high_water));
  }

  mic_ring_set_stream_active(*mic_ring, false);
  clear_active_stream_session_nonce(stream_auth_nonce);

  if (trigger_audio_reinit) {
    // Reinit is coordinated from main loop (shared state + capture gating).
    // Avoid direct reinit from stream worker snapshot context.
  }
}

struct StreamTaskCtx {
  WiFiClient* client;
  int seconds;
  const AppState* state;
  String stream_auth_nonce;
  bool signbench_each_chunk;
  bool enable_telemetry;
  int drop_test_frames;
  TaskHandle_t parent;
};

static void stream_task_entry(void* arg) {
  StreamTaskCtx* ctx = reinterpret_cast<StreamTaskCtx*>(arg);
  handle_stream_impl(*ctx->client, ctx->seconds, *ctx->state, ctx->stream_auth_nonce, ctx->signbench_each_chunk, ctx->enable_telemetry, ctx->drop_test_frames);
  xTaskNotifyGive(ctx->parent);
  vTaskDelete(nullptr);
}

void handle_stream(WiFiClient& client, int seconds, const AppState& state, const String& stream_auth_nonce, bool signbench_each_chunk, bool enable_telemetry, int drop_test_frames) {
  if (state.audio_input_source == "none" || state.audio_sample_rate_hz == 0 || state.audio_channels == 0 || state.audio_sample_width_bytes == 0) {
    String body = "{\"ok\":false,\"error\":\"ERR_AUDIO_UNAVAILABLE\",\"detail\":\"audio capture backend unavailable; codec probe failed\",\"audio_reason\":\"no_codec_detected\",\"audio_codec_probe_attempts\":" +
                  String(state.audio_codec_probe_attempts) +
                  ",\"audio_codec_probe_success_attempt\":" +
                  String(state.audio_codec_probe_success_attempt) +
                  ",\"audio_input_source\":\"" + state.audio_input_source + "\"}";
    send_json(client, 503, body);
    return;
  }

  StreamTaskCtx ctx{&client, seconds, &state, stream_auth_nonce, signbench_each_chunk, enable_telemetry, drop_test_frames, xTaskGetCurrentTaskHandle()};
  BaseType_t ok = xTaskCreatePinnedToCore(stream_task_entry,
                                          "azt_stream",
                                          constants::runtime::kTaskStackStreamWorker,
                                          &ctx,
                                          static_cast<UBaseType_t>(constants::runtime::kTaskPriorityNormal),
                                          nullptr,
                                          kStreamPipelineCore);
  if (ok != pdPASS) {
    send_json(client, 500,
              "{\"ok\":false,\"error\":\"ERR_RUNTIME\",\"detail\":\"failed to start stream task\"}");
    return;
  }
  ulTaskNotifyTake(pdTRUE, portMAX_DELAY);
}

}  // namespace azt
