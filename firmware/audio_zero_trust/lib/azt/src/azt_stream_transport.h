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
  virtual bool uses_http_chunk_transport() const = 0;   // true: transport frames HTTP chunks itself
  virtual bool needs_manual_http_headers() const = 0;   // true for raw WiFiClient HTTP path
  virtual bool send_json_error(int code, const String& body) = 0;
};

class WiFiClientStreamTransport final : public StreamTransport {
 public:
  explicit WiFiClientStreamTransport(WiFiClient& c) : c_(c) {}
  bool connected() const override { return c_.connected(); }
  int available_for_write() const override { return c_.availableForWrite(); }
  bool write_bytes(const uint8_t* data, size_t len) override { return c_.write(data, len) == len; }
  bool write_text(const char* s) override { return c_.print(s) != 0; }
  void flush() override { c_.flush(); }
  bool uses_http_chunk_transport() const override { return false; }
  bool needs_manual_http_headers() const override { return true; }
  bool send_json_error(int code, const String& body) override {
    c_.print("HTTP/1.1 ");
    c_.print(code);
    c_.print(code == 200 ? " OK\r\n" : " Error\r\n");
    c_.print("Content-Type: application/json\r\n");
    c_.print("Connection: close\r\n");
    c_.print("Content-Length: ");
    c_.print(body.length());
    c_.print("\r\n\r\n");
    c_.print(body);
    return true;
  }

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
  bool uses_http_chunk_transport() const override { return true; }
  bool needs_manual_http_headers() const override { return false; }
  bool send_json_error(int code, const String& body) override {
    if (!ok_) return false;
    String status = String(code) + (code == 200 ? " OK" : " Error");
    httpd_resp_set_status(req_, status.c_str());
    httpd_resp_set_type(req_, "application/json");
    if (httpd_resp_send(req_, body.c_str(), body.length()) != ESP_OK) {
      ok_ = false;
      return false;
    }
    return true;
  }
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
