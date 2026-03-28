#include "test_azt_registry.h"

#include <sodium.h>

#include "azt_audio_ring.h"
#include "azt_stream.h"
#include "azt_stream_record.h"
#include "azt_stream_signer.h"

namespace azt_test {
namespace {

bool test_parse_seconds(Context&) {
  return azt::parse_seconds_from_path("/stream") == 0 &&
         azt::parse_seconds_from_path("/stream?seconds=10") == 10 &&
         azt::parse_seconds_from_path("/stream?x=1&seconds=5") == 5 &&
         azt::parse_seconds_from_path("/stream?seconds=0") == 0 &&
         azt::parse_seconds_from_path("/stream?seconds=-7") == 0 &&
         azt::parse_seconds_from_path("/stream?seconds=abc") == 0 &&
         azt::parse_seconds_from_path("/stream?seconds=12x") == 12 &&
         azt::parse_seconds_from_path("/stream?seconds=3&seconds=8") == 3 &&
         azt::parse_seconds_from_path("/stream?seconds=999999") == 86400;
}

bool test_parse_signbench_flag(Context&) {
  return !azt::parse_signbench_from_path("/stream") &&
         !azt::parse_signbench_from_path("/stream?seconds=5") &&
         azt::parse_signbench_from_path("/stream?sigbench=1") &&
         azt::parse_signbench_from_path("/stream?seconds=5&sigbench=true") &&
         !azt::parse_signbench_from_path("/stream?sigbench=0");
}

bool test_parse_drop_test_frames(Context&) {
  return azt::parse_drop_test_frames_from_path("/stream") == 0 &&
         azt::parse_drop_test_frames_from_path("/stream?drop_test_frames=0") == 0 &&
         azt::parse_drop_test_frames_from_path("/stream?drop_test_frames=3") == 3 &&
         azt::parse_drop_test_frames_from_path("/stream?seconds=5&drop_test_frames=17") == 17 &&
         azt::parse_drop_test_frames_from_path("/stream?drop_test_frames=-1") == 0 &&
         azt::parse_drop_test_frames_from_path("/stream?drop_test_frames=abc") == 0;
}

bool test_parse_drop_test_frames_clamp(Context&) {
  return azt::parse_drop_test_frames_from_path("/stream?drop_test_frames=70000") == 65535 &&
         azt::parse_drop_test_frames_from_path("/stream?drop_test_frames=65535") == 65535;
}

bool test_parse_signbench_truthy_variants(Context&) {
  return azt::parse_signbench_from_path("/stream?sigbench=YES") &&
         azt::parse_signbench_from_path("/stream?sigbench=On") &&
         !azt::parse_signbench_from_path("/stream?sigbench=off") &&
         !azt::parse_signbench_from_path("/stream?sigbench=2");
}

bool test_parse_seconds_without_query(Context&) {
  return azt::parse_seconds_from_path("/stream/seconds=5") == 0 &&
         azt::parse_seconds_from_path("/streamseconds=5") == 0;
}

bool test_parse_seconds_query_order(Context&) {
  return azt::parse_seconds_from_path("/stream?x=1&seconds=6&y=2") == 6 &&
         azt::parse_seconds_from_path("/stream?seconds=6&x=1") == 6;
}

bool test_max_contiguous_drop_frames_policy(Context&) {
  // 512 samples/frame at 16kHz => 32ms per frame, 10s budget => 312 frames (floor).
  return azt::max_contiguous_drop_frames_for_config(512, 10000, 16000) == 312 &&
         azt::max_contiguous_drop_frames_for_config(0, 10000, 16000) == 1 &&
         azt::max_contiguous_drop_frames_for_config(512, 10000, 0) == 1;
}

bool test_should_disconnect_for_contiguous_drop(Context&) {
  uint32_t threshold = azt::max_contiguous_drop_frames_for_config(512, 10000, 16000);
  return !azt::should_disconnect_for_contiguous_drop(threshold - 1, 512, 10000, 16000) &&
         azt::should_disconnect_for_contiguous_drop(threshold, 512, 10000, 16000);
}

bool test_account_drop_event(Context&) {
  uint32_t pending = 5;
  uint64_t total = 9;
  uint32_t contiguous = 2;
  azt::account_drop_event(3, pending, total, contiguous);
  return pending == 8 && total == 12 && contiguous == 5;
}

bool test_apply_drop_and_check_stall(Context&) {
  uint32_t pending = 0;
  uint64_t total = 0;
  uint32_t contiguous = 0;

  uint32_t threshold = azt::max_contiguous_drop_frames_for_config(512, 10000, 16000);
  bool stall = false;
  for (uint32_t i = 0; i + 1 < threshold; ++i) {
    stall = azt::apply_drop_and_check_stall(1, 512, pending, total, contiguous, 10000, 16000);
    if (stall) return false;
  }
  stall = azt::apply_drop_and_check_stall(1, 512, pending, total, contiguous, 10000, 16000);
  return stall && pending == threshold && total == threshold && contiguous == threshold;
}

bool test_evaluate_stream_loop_branch(Context&) {
  auto d_ing = azt::evaluate_stream_loop_branch(true, false, false, false, 1, 512, 10000, 16000);
  if (!d_ing.emit_drop_notice || d_ing.skip_audio_send) return false;

  auto d_drop_test = azt::evaluate_stream_loop_branch(false, true, false, false, 1, 512, 10000, 16000);
  if (!d_drop_test.skip_audio_send) return false;

  auto d_low_write = azt::evaluate_stream_loop_branch(false, false, true, false, 1, 512, 10000, 16000);
  if (!d_low_write.skip_audio_send) return false;

  uint32_t threshold = azt::max_contiguous_drop_frames_for_config(512, 10000, 16000);
  auto d_stall = azt::evaluate_stream_loop_branch(false, false, false, true, threshold, 512, 10000, 16000);
  return d_stall.skip_audio_send && d_stall.disconnect_for_stall;
}

bool test_stream_backpressure_helpers(Context&) {
  if (!azt::should_defer_drop_notice_for_backpressure(1, 64)) return false;
  if (azt::should_defer_drop_notice_for_backpressure(64, 64)) return false;
  if (azt::should_defer_drop_notice_for_backpressure(0, 64)) return false;

  if (!azt::is_low_write_capacity(1, 32)) return false;
  if (azt::is_low_write_capacity(32, 32)) return false;
  return !azt::is_low_write_capacity(0, 32);
}

bool test_sig_interval_adaptation(Context&) {
  uint32_t i = 10;
  i = azt::sig_checkpoint_interval_on_missed_response(i, 10, 160);  // 20
  i = azt::sig_checkpoint_interval_on_missed_response(i, 10, 160);  // 40
  i = azt::sig_checkpoint_interval_on_missed_response(i, 10, 160);  // 80
  i = azt::sig_checkpoint_interval_on_missed_response(i, 10, 160);  // 160
  i = azt::sig_checkpoint_interval_on_missed_response(i, 10, 160);  // stays 160
  if (i != 160) return false;

  i = azt::sig_checkpoint_interval_on_response(i, 10);  // 80
  i = azt::sig_checkpoint_interval_on_response(i, 10);  // 40
  i = azt::sig_checkpoint_interval_on_response(i, 10);  // 20
  i = azt::sig_checkpoint_interval_on_response(i, 10);  // 10
  i = azt::sig_checkpoint_interval_on_response(i, 10);  // stays 10
  return i == 10;
}

bool test_telemetry_accumulator_window_and_snapshot(Context&) {
  azt::TelemetryAccumulator a{};
  azt::telemetry_accumulate_level(a, 3);
  azt::telemetry_accumulate_level(a, 7);
  azt::telemetry_accumulate_level(a, 11);

  if (!azt::telemetry_window_ready(a, 3)) return false;
  auto t = azt::telemetry_snapshot_from_acc(a);
  if (t.window_blocks != 3 || t.rb_level_min != 3 || t.rb_level_max != 11 || t.rb_level_last != 11) return false;
  if (t.rb_level_avg_q8 != static_cast<uint16_t>(((3 + 7 + 11) * 256ULL) / 3ULL)) return false;

  azt::telemetry_reset(a);
  return !azt::telemetry_window_ready(a, 1) && a.samples == 0 && a.level_min == 0xFFFF;
}

bool test_telemetry_snapshot_empty_defaults(Context&) {
  azt::TelemetryAccumulator a{};
  auto t = azt::telemetry_snapshot_from_acc(a);
  return t.window_blocks == 0 && t.rb_level_min == 0 && t.rb_level_max == 0 &&
         t.rb_level_last == 0 && t.rb_level_avg_q8 == 0;
}

bool test_ring_drop_newest_policy(Context&) {
  auto* rb = new azt::MicRing();
  if (!rb) return false;

  for (size_t i = 0; i < azt::kMicRingFrames; ++i) {
    uint8_t b = static_cast<uint8_t>(i & 0xFF);
    if (!azt::mic_ring_push_drop_newest(*rb, &b, 1)) {
      delete rb;
      return false;
    }
  }

  uint8_t newest = 0xEE;
  if (azt::mic_ring_push_drop_newest(*rb, &newest, 1)) {
    delete rb;
    return false;
  }

  if (rb->high_water != azt::kMicRingFrames) {
    delete rb;
    return false;
  }

  for (size_t i = 0; i < azt::kMicRingFrames; ++i) {
    azt::MicFrame f;
    if (!azt::mic_ring_pop(*rb, f) || f.len != 1 || f.data[0] != static_cast<uint8_t>(i & 0xFF)) {
      delete rb;
      return false;
    }
  }

  azt::MicFrame empty;
  bool ok = !azt::mic_ring_pop(*rb, empty);
  delete rb;
  return ok;
}

bool test_ring_overflow_accounting(Context&) {
  auto* rb = new azt::MicRing();
  if (!rb) return false;
  uint8_t b = 0x2A;

  for (size_t i = 0; i < azt::kMicRingFrames; ++i) {
    if (!azt::mic_ring_push_drop_newest(*rb, &b, 1)) {
      delete rb;
      return false;
    }
  }
  for (size_t i = 0; i < 7; ++i) {
    if (azt::mic_ring_push_drop_newest(*rb, &b, 1)) {
      delete rb;
      return false;
    }
  }

  auto stats = azt::mic_ring_snapshot_stats(*rb);
  delete rb;
  return stats.dropped_newest == 7;
}

bool test_ring_take_dropped_reset(Context&) {
  auto* rb = new azt::MicRing();
  if (!rb) return false;
  uint8_t b = 0x33;

  for (size_t i = 0; i < azt::kMicRingFrames; ++i) {
    if (!azt::mic_ring_push_drop_newest(*rb, &b, 1)) {
      delete rb;
      return false;
    }
  }
  for (size_t i = 0; i < 3; ++i) {
    (void)azt::mic_ring_push_drop_newest(*rb, &b, 1);
  }

  uint64_t d1 = azt::mic_ring_take_dropped_newest(*rb);
  uint64_t d2 = azt::mic_ring_take_dropped_newest(*rb);
  delete rb;
  return d1 == 3 && d2 == 0;
}

bool test_ring_drain_refill_fifo(Context&) {
  auto* rb = new azt::MicRing();
  if (!rb) return false;

  for (uint8_t i = 0; i < 10; ++i) {
    if (!azt::mic_ring_push_drop_newest(*rb, &i, 1)) {
      delete rb;
      return false;
    }
  }

  for (uint8_t i = 0; i < 4; ++i) {
    azt::MicFrame f;
    if (!azt::mic_ring_pop(*rb, f) || f.data[0] != i) {
      delete rb;
      return false;
    }
  }

  for (uint8_t i = 10; i < 14; ++i) {
    if (!azt::mic_ring_push_drop_newest(*rb, &i, 1)) {
      delete rb;
      return false;
    }
  }

  for (uint8_t exp = 4; exp < 14; ++exp) {
    azt::MicFrame f;
    if (!azt::mic_ring_pop(*rb, f) || f.data[0] != exp) {
      delete rb;
      return false;
    }
  }

  azt::MicFrame empty;
  bool ok = !azt::mic_ring_pop(*rb, empty);
  delete rb;
  return ok;
}

bool test_telemetry_snapshot_body_format(Context&) {
  azt::TelemetrySnapshotV1 t{};
  t.window_blocks = 50;
  t.rb_level_min = 1;
  t.rb_level_max = 31;
  t.rb_level_avg_q8 = 1234;
  t.rb_level_last = 7;

  std::vector<uint8_t> out;
  azt::encode_telemetry_snapshot_body_v1(t, out);
  if (out.size() != 11) return false;
  if (out[0] != 1) return false;
  if (out[1] != 0 || out[2] != 50) return false;
  if (out[3] != 0 || out[4] != 1) return false;
  if (out[5] != 0 || out[6] != 31) return false;
  if (out[7] != static_cast<uint8_t>((1234 >> 8) & 0xFF) || out[8] != static_cast<uint8_t>(1234 & 0xFF)) return false;
  if (out[9] != 0 || out[10] != 7) return false;
  return true;
}

bool signer_wait_poll(azt::StreamSigner& signer, azt::SignResponse& out, uint32_t timeout_ms) {
  uint32_t start = millis();
  while (millis() - start < timeout_ms) {
    if (signer.poll(out)) return true;
    delay(2);
  }
  return false;
}

bool test_stream_signer_begin_poll_empty_stop(Context&) {
  uint8_t seed[32] = {0};
  unsigned char pk[crypto_sign_ed25519_PUBLICKEYBYTES];
  unsigned char sk[crypto_sign_ed25519_SECRETKEYBYTES];
  if (crypto_sign_ed25519_seed_keypair(pk, sk, seed) != 0) return false;

  azt::StreamSigner signer;
  if (!signer.begin(sk, xTaskGetCurrentTaskHandle(), 0)) return false;

  azt::SignResponse out{};
  bool empty = !signer.poll(out);
  signer.stop();
  signer.stop();
  return empty;
}

bool test_stream_signer_submit_and_verify(Context&) {
  uint8_t seed[32] = {0};
  for (size_t i = 0; i < sizeof(seed); ++i) seed[i] = static_cast<uint8_t>(i + 1);

  unsigned char pk[crypto_sign_ed25519_PUBLICKEYBYTES];
  unsigned char sk[crypto_sign_ed25519_SECRETKEYBYTES];
  if (crypto_sign_ed25519_seed_keypair(pk, sk, seed) != 0) return false;

  azt::StreamSigner signer;
  if (!signer.begin(sk, xTaskGetCurrentTaskHandle(), 0)) return false;

  uint8_t chain_v[32];
  for (size_t i = 0; i < sizeof(chain_v); ++i) chain_v[i] = static_cast<uint8_t>(0xA0 + i);
  uint32_t ref_seq = 1234;
  signer.submit(ref_seq, chain_v);

  azt::SignResponse out{};
  bool got = signer_wait_poll(signer, out, 1500);
  signer.stop();
  if (!got) return false;
  if (out.ref_seq != ref_seq) return false;

  uint8_t msg[8 + 4 + 32];
  memcpy(msg, "AZT1SIG1", 8);
  msg[8] = static_cast<uint8_t>((ref_seq >> 24) & 0xFF);
  msg[9] = static_cast<uint8_t>((ref_seq >> 16) & 0xFF);
  msg[10] = static_cast<uint8_t>((ref_seq >> 8) & 0xFF);
  msg[11] = static_cast<uint8_t>(ref_seq & 0xFF);
  memcpy(msg + 12, chain_v, 32);

  return crypto_sign_ed25519_verify_detached(out.sig64, msg, sizeof(msg), pk) == 0;
}

bool test_stream_signer_submit_overwrite_latest(Context&) {
  uint8_t seed[32] = {0};
  for (size_t i = 0; i < sizeof(seed); ++i) seed[i] = static_cast<uint8_t>(0xF0 + i);

  unsigned char pk[crypto_sign_ed25519_PUBLICKEYBYTES];
  unsigned char sk[crypto_sign_ed25519_SECRETKEYBYTES];
  if (crypto_sign_ed25519_seed_keypair(pk, sk, seed) != 0) return false;

  azt::StreamSigner signer;
  if (!signer.begin(sk, xTaskGetCurrentTaskHandle(), 0)) return false;

  uint8_t chain1[32] = {1};
  uint8_t chain2[32] = {2};
  signer.submit(10, chain1);
  signer.submit(20, chain2);

  azt::SignResponse out{};
  bool got = signer_wait_poll(signer, out, 1500);
  signer.stop();
  if (!got) return false;

  // With single request slot overwrite semantics, latest submit should win.
  return out.ref_seq == 20;
}

bool test_stream_signer_rapid_submit_keeps_latest(Context&) {
  uint8_t seed[32] = {0};
  for (size_t i = 0; i < sizeof(seed); ++i) seed[i] = static_cast<uint8_t>(0x40 + i);

  unsigned char pk[crypto_sign_ed25519_PUBLICKEYBYTES];
  unsigned char sk[crypto_sign_ed25519_SECRETKEYBYTES];
  if (crypto_sign_ed25519_seed_keypair(pk, sk, seed) != 0) return false;

  azt::StreamSigner signer;
  if (!signer.begin(sk, xTaskGetCurrentTaskHandle(), 0)) return false;

  uint8_t chain[32] = {0};
  for (uint32_t i = 1; i <= 64; ++i) {
    chain[0] = static_cast<uint8_t>(i & 0xFF);
    signer.submit(i, chain);
  }

  azt::SignResponse out{};
  bool got = signer_wait_poll(signer, out, 1500);
  signer.stop();
  if (!got) return false;

  return out.ref_seq == 64;
}

bool test_stream_signer_poll_drains_to_empty(Context&) {
  uint8_t seed[32] = {0};
  for (size_t i = 0; i < sizeof(seed); ++i) seed[i] = static_cast<uint8_t>(0x90 + i);

  unsigned char pk[crypto_sign_ed25519_PUBLICKEYBYTES];
  unsigned char sk[crypto_sign_ed25519_SECRETKEYBYTES];
  if (crypto_sign_ed25519_seed_keypair(pk, sk, seed) != 0) return false;

  azt::StreamSigner signer;
  if (!signer.begin(sk, xTaskGetCurrentTaskHandle(), 0)) return false;

  uint8_t chain[32] = {0x11};
  signer.submit(77, chain);

  azt::SignResponse out{};
  bool got = signer_wait_poll(signer, out, 1500);
  if (!got || out.ref_seq != 77) {
    signer.stop();
    return false;
  }

  bool now_empty = !signer.poll(out);
  signer.stop();
  return now_empty;
}

bool test_stream_signer_submit_then_immediate_stop_is_safe(Context&) {
  uint8_t seed[32] = {0};
  for (size_t i = 0; i < sizeof(seed); ++i) seed[i] = static_cast<uint8_t>(0x20 + i);

  unsigned char pk[crypto_sign_ed25519_PUBLICKEYBYTES];
  unsigned char sk[crypto_sign_ed25519_SECRETKEYBYTES];
  if (crypto_sign_ed25519_seed_keypair(pk, sk, seed) != 0) return false;

  azt::StreamSigner signer;
  if (!signer.begin(sk, xTaskGetCurrentTaskHandle(), 0)) return false;

  uint8_t chain[32] = {0x55};
  signer.submit(999, chain);
  signer.stop();
  signer.stop();

  azt::SignResponse out{};
  return !signer.poll(out);
}

}  // namespace

void register_test_azt_stream(Registry& out) {
  out.push_back({"PARSE_SECONDS", test_parse_seconds, "parse_seconds behavior mismatch"});
  out.push_back({"PARSE_SIGNBENCH_FLAG", test_parse_signbench_flag, "sigbench parser mismatch"});
  out.push_back({"PARSE_DROP_TEST_FRAMES", test_parse_drop_test_frames, "drop_test_frames parser mismatch"});
  out.push_back({"PARSE_DROP_TEST_FRAMES_CLAMP", test_parse_drop_test_frames_clamp, "drop_test_frames clamp mismatch"});
  out.push_back({"PARSE_SIGNBENCH_TRUTHY_VARIANTS", test_parse_signbench_truthy_variants, "sigbench truthy parser mismatch"});
  out.push_back({"PARSE_SECONDS_WITHOUT_QUERY", test_parse_seconds_without_query, "seconds parser should ignore non-query forms"});
  out.push_back({"PARSE_SECONDS_QUERY_ORDER", test_parse_seconds_query_order, "seconds parser query-order mismatch"});
  out.push_back({"MAX_CONTIGUOUS_DROP_FRAMES_POLICY", test_max_contiguous_drop_frames_policy, "max contiguous drop frame threshold policy mismatch"});
  out.push_back({"SHOULD_DISCONNECT_FOR_CONTIGUOUS_DROP", test_should_disconnect_for_contiguous_drop, "contiguous drop disconnect policy mismatch"});
  out.push_back({"ACCOUNT_DROP_EVENT", test_account_drop_event, "drop event accounting mismatch"});
  out.push_back({"APPLY_DROP_AND_CHECK_STALL", test_apply_drop_and_check_stall, "drop-and-stall policy application mismatch"});
  out.push_back({"EVALUATE_STREAM_LOOP_BRANCH", test_evaluate_stream_loop_branch, "stream loop branch decision policy mismatch"});
  out.push_back({"STREAM_BACKPRESSURE_HELPERS", test_stream_backpressure_helpers, "stream backpressure helper policy mismatch"});
  out.push_back({"SIG_INTERVAL_ADAPTATION", test_sig_interval_adaptation, "signature checkpoint interval adaptation mismatch"});
  out.push_back({"TELEMETRY_ACCUMULATOR_WINDOW_AND_SNAPSHOT", test_telemetry_accumulator_window_and_snapshot, "telemetry accumulator/snapshot behavior mismatch"});
  out.push_back({"TELEMETRY_SNAPSHOT_EMPTY_DEFAULTS", test_telemetry_snapshot_empty_defaults, "empty telemetry snapshot defaults mismatch"});
  out.push_back({"RING_DROP_NEWEST_POLICY", test_ring_drop_newest_policy, "ring should drop newest on overflow"});
  out.push_back({"RING_OVERFLOW_ACCOUNTING", test_ring_overflow_accounting, "ring drop counter mismatch"});
  out.push_back({"RING_TAKE_DROPPED_RESET", test_ring_take_dropped_reset, "ring dropped counter reset mismatch"});
  out.push_back({"RING_DRAIN_REFILL_FIFO", test_ring_drain_refill_fifo, "ring fifo drain/refill mismatch"});
  out.push_back({"TELEMETRY_SNAPSHOT_BODY_FORMAT", test_telemetry_snapshot_body_format, "telemetry snapshot body format mismatch"});
  out.push_back({"STREAM_SIGNER_BEGIN_POLL_EMPTY_STOP", test_stream_signer_begin_poll_empty_stop, "stream signer begin/poll-empty/stop behavior mismatch"});
  out.push_back({"STREAM_SIGNER_SUBMIT_AND_VERIFY", test_stream_signer_submit_and_verify, "stream signer submit/verify contract mismatch"});
  out.push_back({"STREAM_SIGNER_SUBMIT_OVERWRITE_LATEST", test_stream_signer_submit_overwrite_latest, "stream signer request overwrite semantics mismatch"});
  out.push_back({"STREAM_SIGNER_RAPID_SUBMIT_KEEPS_LATEST", test_stream_signer_rapid_submit_keeps_latest, "stream signer rapid submit should preserve latest request semantics"});
  out.push_back({"STREAM_SIGNER_POLL_DRAINS_TO_EMPTY", test_stream_signer_poll_drains_to_empty, "stream signer poll should drain one-shot response queue"});
  out.push_back({"STREAM_SIGNER_SUBMIT_THEN_IMMEDIATE_STOP_IS_SAFE", test_stream_signer_submit_then_immediate_stop_is_safe, "stream signer should tolerate submit/stop race and idempotent stop"});
}

}  // namespace azt_test
