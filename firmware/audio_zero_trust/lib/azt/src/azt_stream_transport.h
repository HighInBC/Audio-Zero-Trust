#pragma once

#include <Arduino.h>
#include <WiFiClient.h>
#include <esp_http_server.h>

namespace azt {

class StreamTransport {
 public:
  virtual ~StreamTransport() = default;
  virtual bool connected() const = 0;
  virtual int available_for_write() const = 0;
  virtual bool write_bytes(const uint8_t* data, size_t len) = 0;
  virtual bool write_text(const char* s) = 0;
  virtual void flush() = 0;
};

class WiFiClientStreamTransport final : public StreamTransport {
 public:
  explicit WiFiClientStreamTransport(WiFiClient& c) : c_(c) {}
  bool connected() const override { return c_.connected(); }
  int available_for_write() const override { return c_.availableForWrite(); }
  bool write_bytes(const uint8_t* data, size_t len) override { return c_.write(data, len) == len; }
  bool write_text(const char* s) override { return c_.print(s) != 0; }
  void flush() override { c_.flush(); }

 private:
  WiFiClient& c_;
};

class HttpsChunkedStreamTransport final : public StreamTransport {
 public:
  explicit HttpsChunkedStreamTransport(httpd_req_t* req) : req_(req), ok_(req != nullptr) {}

  bool connected() const override { return ok_; }
  int available_for_write() const override { return 4096; }
  bool write_bytes(const uint8_t* data, size_t len) override {
    if (!ok_) return false;
    if (len == 0) return true;
    if (httpd_resp_send_chunk(req_, reinterpret_cast<const char*>(data), len) != ESP_OK) {
      ok_ = false;
      return false;
    }
    return true;
  }
  bool write_text(const char* s) override {
    if (!ok_) return false;
    if (!s) return true;
    return write_bytes(reinterpret_cast<const uint8_t*>(s), strlen(s));
  }
  void flush() override {}
  bool finish() {
    if (!ok_) return false;
    if (httpd_resp_send_chunk(req_, nullptr, 0) != ESP_OK) {
      ok_ = false;
      return false;
    }
    return true;
  }

 private:
  httpd_req_t* req_;
  bool ok_;
};

}  // namespace azt
