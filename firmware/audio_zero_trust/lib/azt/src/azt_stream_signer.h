#pragma once

#include <Arduino.h>
#include <sodium.h>

namespace azt {

struct SignResponse {
  uint32_t ref_seq = 0;
  uint8_t sig64[64] = {0};
};

class StreamSigner {
 public:
  bool begin(const unsigned char sign_sk[crypto_sign_ed25519_SECRETKEYBYTES], TaskHandle_t parent, BaseType_t core);
  void stop();
  void submit(uint32_t ref_seq, const uint8_t chain_v[32]);
  bool poll(SignResponse& out);

 private:
  struct SignRequestSlot {
    bool has_request = false;
    uint32_t ref_seq = 0;
    uint8_t chain_v[32] = {0};
  };

  struct SignerTaskCtx {
    SignRequestSlot* slot;
    portMUX_TYPE* slot_mux;
    QueueHandle_t out_q;
    TaskHandle_t parent;
    volatile bool* stop;
    TaskHandle_t* stop_waiter;
    unsigned char sk[crypto_sign_ed25519_SECRETKEYBYTES];
  };

  static void signer_task_entry(void* arg);

  SignRequestSlot slot_{};
  portMUX_TYPE slot_mux_ = portMUX_INITIALIZER_UNLOCKED;
  QueueHandle_t out_q_ = nullptr;
  TaskHandle_t task_ = nullptr;
  volatile bool stop_ = false;
  TaskHandle_t stop_waiter_ = nullptr;
  SignerTaskCtx ctx_{};
};

}  // namespace azt
