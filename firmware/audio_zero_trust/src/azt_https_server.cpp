#include "azt_https_server.h"

#include <Preferences.h>
#include <WiFi.h>
#include <esp_https_server.h>
#include <esp_system.h>
#include <freertos/FreeRTOS.h>
#include <memory>
#include <lwip/sockets.h>
#include <lwip/inet.h>

#include "azt_http_api.h"
#include "azt_stream.h"

namespace azt {

namespace {
httpd_handle_t g_https = nullptr;
AppState* g_state = nullptr;
SemaphoreHandle_t g_state_mu = nullptr;
String g_cert;
String g_key;

static String https_remote_ip(httpd_req_t* req) {
  if (!req) return String("");
  int fd = httpd_req_to_sockfd(req);
  if (fd < 0) return String("");

  struct sockaddr_storage ss;
  socklen_t slen = sizeof(ss);
  if (getpeername(fd, reinterpret_cast<struct sockaddr*>(&ss), &slen) != 0) return String("");

  char ipbuf[INET6_ADDRSTRLEN] = {0};
  if (ss.ss_family == AF_INET) {
    auto* a = reinterpret_cast<struct sockaddr_in*>(&ss);
    if (!inet_ntop(AF_INET, &a->sin_addr, ipbuf, sizeof(ipbuf))) return String("");
    return String(ipbuf);
  }
  if (ss.ss_family == AF_INET6) {
    auto* a6 = reinterpret_cast<struct sockaddr_in6*>(&ss);
    if (!inet_ntop(AF_INET6, &a6->sin6_addr, ipbuf, sizeof(ipbuf))) return String("");
    return String(ipbuf);
  }
  return String("");
}

static esp_err_t handle_https_any(httpd_req_t* req) {
  if (!req || !g_state || !g_state_mu) return ESP_FAIL;

  String method = (req->method == HTTP_GET) ? "GET" : (req->method == HTTP_POST ? "POST" : "");
  if (method.length() == 0) {
    httpd_resp_set_status(req, "405 Method Not Allowed");
    httpd_resp_sendstr(req, "{\"ok\":false,\"error\":\"ERR_METHOD\"}");
    return ESP_OK;
  }

  String path = String(req->uri ? req->uri : "");
  size_t qlen = httpd_req_get_url_query_len(req);
  if (qlen > 0) {
    std::unique_ptr<char[]> q(new char[qlen + 1]);
    if (httpd_req_get_url_query_str(req, q.get(), qlen + 1) == ESP_OK) {
      path += "?";
      path += q.get();
    }
  }

  if (path.startsWith("/stream")) {
    String location = String("http://") + WiFi.localIP().toString() + String(":8081") + path;
    httpd_resp_set_status(req, "307 Temporary Redirect");
    httpd_resp_set_hdr(req, "Location", location.c_str());
    httpd_resp_send(req, nullptr, 0);
    return ESP_OK;
  }

  if (path == "/api/v0/device/upgrade") {
    httpd_resp_set_status(req, "400 Bad Request");
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, "{\"ok\":false,\"error\":\"ERR_OTA_HTTPS_UNSUPPORTED\",\"detail\":\"OTA upgrade over HTTPS endpoint not implemented yet\"}");
    return ESP_OK;
  }

  String body = "";
  if (req->content_len > 0) {
    body.reserve(static_cast<size_t>(req->content_len));
    int remain = req->content_len;
    char buf[512];
    while (remain > 0) {
      int want = remain > static_cast<int>(sizeof(buf)) ? static_cast<int>(sizeof(buf)) : remain;
      int n = httpd_req_recv(req, buf, want);
      if (n <= 0) {
        httpd_resp_set_status(req, "400 Bad Request");
        httpd_resp_set_type(req, "application/json");
        httpd_resp_sendstr(req, "{\"ok\":false,\"error\":\"ERR_BODY_READ\"}");
        return ESP_OK;
      }
      body.concat(String(buf).substring(0, n));
      remain -= n;
    }
  }

  if (xSemaphoreTake(g_state_mu, pdMS_TO_TICKS(4000)) != pdTRUE) {
    httpd_resp_set_status(req, "503 Service Unavailable");
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, "{\"ok\":false,\"error\":\"ERR_STATE_LOCK\"}");
    return ESP_OK;
  }
  String remote_ip = https_remote_ip(req);
  HttpDispatchResult r = dispatch_request(method, path, body, *g_state, remote_ip);
  xSemaphoreGive(g_state_mu);

  String status = String(r.code) + (r.code == 200 ? " OK" : " Error");
  httpd_resp_set_status(req, status.c_str());
  httpd_resp_set_type(req, r.content_type.c_str());
  httpd_resp_send(req, r.body.c_str(), r.body.length());

  if (r.reboot_after_response) {
    request_stream_shutdown();
    vTaskDelay(pdMS_TO_TICKS(300));
    esp_restart();
  }

  return ESP_OK;
}

}  // namespace

bool start_https_api_server(AppState* state, SemaphoreHandle_t state_mu, uint16_t port) {
  if (g_https) return true;
  if (!state || !state_mu) return false;

  Preferences p;
  if (!p.begin("aztcfg", true)) return false;
  g_cert = p.getString("tls_srv_cert", "");
  g_key = p.getString("tls_srv_key", "");
  p.end();
  if (g_cert.length() == 0 || g_key.length() == 0) return false;

  g_state = state;
  g_state_mu = state_mu;

  httpd_ssl_config_t conf = HTTPD_SSL_CONFIG_DEFAULT();
  conf.port_secure = port;
  conf.port_insecure = 0;
  conf.httpd.uri_match_fn = httpd_uri_match_wildcard;
  conf.cacert_pem = reinterpret_cast<const unsigned char*>(g_cert.c_str());
  conf.cacert_len = g_cert.length() + 1;
  conf.prvtkey_pem = reinterpret_cast<const unsigned char*>(g_key.c_str());
  conf.prvtkey_len = g_key.length() + 1;

  if (httpd_ssl_start(&g_https, &conf) != ESP_OK) {
    g_https = nullptr;
    return false;
  }

  httpd_uri_t get_any = {};
  get_any.uri = "/*";
  get_any.method = HTTP_GET;
  get_any.handler = handle_https_any;
  if (httpd_register_uri_handler(g_https, &get_any) != ESP_OK) return false;

  httpd_uri_t post_any = {};
  post_any.uri = "/*";
  post_any.method = HTTP_POST;
  post_any.handler = handle_https_any;
  if (httpd_register_uri_handler(g_https, &post_any) != ESP_OK) return false;

  return true;
}

void stop_https_api_server() {
  if (g_https) {
    httpd_ssl_stop(g_https);
    g_https = nullptr;
  }
}

bool https_api_server_running() { return g_https != nullptr; }

}  // namespace azt
