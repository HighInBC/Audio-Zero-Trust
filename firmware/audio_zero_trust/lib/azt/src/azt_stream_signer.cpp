#include "azt_stream_signer.h"

namespace azt {

void StreamSigner::signer_task_entry(void* arg) {
  auto* ctx = reinterpret_cast<SignerTaskCtx*>(arg);

  while (!(*ctx->stop)) {
    ulTaskNotifyTake(pdTRUE, pdMS_TO_TICKS(200));
    if (*ctx->stop) break;

    SignRequestSlot req;
    bool has = false;
    portENTER_CRITICAL(ctx->slot_mux);
    if (ctx->slot->has_request) {
      req = *ctx->slot;
      ctx->slot->has_request = false;
      has = true;
    }
    portEXIT_CRITICAL(ctx->slot_mux);
    if (!has) continue;

    uint8_t msg[8 + 4 + 32];
    memcpy(msg, "AZT1SIG1", 8);
    msg[8] = static_cast<uint8_t>((req.ref_seq >> 24) & 0xFF);
    msg[9] = static_cast<uint8_t>((req.ref_seq >> 16) & 0xFF);
    msg[10] = static_cast<uint8_t>((req.ref_seq >> 8) & 0xFF);
    msg[11] = static_cast<uint8_t>(req.ref_seq & 0xFF);
    memcpy(msg + 12, req.chain_v, 32);

    SignResponse resp{};
    resp.ref_seq = req.ref_seq;
    unsigned long long sig_len = 0;
    if (crypto_sign_ed25519_detached(resp.sig64, &sig_len, msg, sizeof(msg), ctx->sk) == 0 &&
        sig_len == crypto_sign_ed25519_BYTES) {
      bool newer_pending = false;
      portENTER_CRITICAL(ctx->slot_mux);
      newer_pending = ctx->slot->has_request;
      portEXIT_CRITICAL(ctx->slot_mux);

      // Drop stale response if newer submit arrived while signing.
      if (!newer_pending) {
        xQueueOverwrite(ctx->out_q, &resp);
        xTaskNotifyGive(ctx->parent);
      }
    }
  }

  if (ctx->stop_waiter && *ctx->stop_waiter) {
    xTaskNotifyGive(*ctx->stop_waiter);
  }
  vTaskDelete(nullptr);
}

bool StreamSigner::begin(const unsigned char sign_sk[crypto_sign_ed25519_SECRETKEYBYTES],
                         TaskHandle_t parent,
                         BaseType_t core) {
  out_q_ = xQueueCreate(1, sizeof(SignResponse));
  if (!out_q_) return false;

  stop_ = false;
  stop_waiter_ = nullptr;
  ctx_.slot = &slot_;
  ctx_.slot_mux = &slot_mux_;
  ctx_.out_q = out_q_;
  ctx_.parent = parent;
  ctx_.stop = &stop_;
  ctx_.stop_waiter = &stop_waiter_;
  memcpy(ctx_.sk, sign_sk, sizeof(ctx_.sk));

  if (xTaskCreatePinnedToCore(signer_task_entry,
                              "azt_signer",
                              8192,
                              &ctx_,
                              1,
                              &task_,
                              core) != pdPASS) {
    vQueueDelete(out_q_);
    out_q_ = nullptr;
    return false;
  }
  return true;
}

void StreamSigner::submit(uint32_t ref_seq, const uint8_t chain_v[32]) {
  bool should_notify = false;
  portENTER_CRITICAL(&slot_mux_);
  if (!stop_) {
    slot_.has_request = true;
    slot_.ref_seq = ref_seq;
    memcpy(slot_.chain_v, chain_v, 32);
    should_notify = (task_ != nullptr);
  }
  portEXIT_CRITICAL(&slot_mux_);
  if (should_notify) xTaskNotifyGive(task_);
}

bool StreamSigner::poll(SignResponse& out) {
  if (!out_q_) return false;
  return xQueueReceive(out_q_, &out, 0) == pdTRUE;
}

void StreamSigner::stop() {
  TaskHandle_t task = nullptr;
  TaskHandle_t waiter = xTaskGetCurrentTaskHandle();

  portENTER_CRITICAL(&slot_mux_);
  stop_ = true;
  stop_waiter_ = waiter;
  task = task_;
  portEXIT_CRITICAL(&slot_mux_);

  if (task) {
    xTaskNotifyGive(task);
    // Wait for signer task to explicitly ack shutdown.
    (void)ulTaskNotifyTake(pdTRUE, pdMS_TO_TICKS(250));

    // Defensive: the parent task may receive unrelated notifications; verify
    // the signer task actually exited before reclaiming shared resources.
    const uint32_t deadline = millis() + 200;
    while (eTaskGetState(task) != eDeleted && static_cast<int32_t>(deadline - millis()) > 0) {
      vTaskDelay(pdMS_TO_TICKS(5));
    }
    if (eTaskGetState(task) != eDeleted) {
      vTaskDelete(task);
    }
    task_ = nullptr;
  }

  portENTER_CRITICAL(&slot_mux_);
  stop_waiter_ = nullptr;
  slot_.has_request = false;
  portEXIT_CRITICAL(&slot_mux_);

  if (out_q_) {
    vQueueDelete(out_q_);
    out_q_ = nullptr;
  }
}

}  // namespace azt
