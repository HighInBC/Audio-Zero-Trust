#include "azt_https_server.h"

#include <Preferences.h>
#include <WiFi.h>
#include <esp_https_server.h>
#include <esp_system.h>
#include <freertos/FreeRTOS.h>
#include <memory>

#include "azt_http_api.h"
#include "azt_stream.h"
#include "azt_stream_transport.h"

namespace {
String json_escape_for_error(const String& in) {
  String out = "\"";
  for (size_t i = 0; i < in.length(); ++i) {
    char c = in.charAt(i);
    if (c == '\\' || c == '"') out += '\\';
    if (c == '\n') out += "\\n";
    else if (c == '\r') out += "\\r";
    else out += c;
  }
  out += "\"";
  return out;
}
}  // namespace

namespace azt {

namespace {
httpd_handle_t g_https = nullptr;
AppState* g_state = nullptr;
SemaphoreHandle_t g_state_mu = nullptr;
String g_cert;
String g_key;

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
    if (xSemaphoreTake(g_state_mu, pdMS_TO_TICKS(4000)) != pdTRUE) {
      httpd_resp_set_status(req, "503 Service Unavailable");
      httpd_resp_set_type(req, "application/json");
      httpd_resp_sendstr(req, "{\"ok\":false,\"error\":\"ERR_STATE_LOCK\"}");
      return ESP_OK;
    }
    AppState state_snapshot = *g_state;
    xSemaphoreGive(g_state_mu);

    int seconds = parse_seconds_from_path(path);
    bool sigbench = parse_signbench_from_path(path);
    bool telemetry = path.indexOf("telemetry=1") >= 0;
    int drop_test_frames = parse_drop_test_frames_from_path(path);

    HttpsChunkedStreamTransport transport(req);
    handle_stream_transport(transport, seconds, state_snapshot, sigbench, telemetry, drop_test_frames);
    (void)transport.finish();
    return ESP_OK;
  }

  if (method == "GET" && path == "/api/v0/device/upgrade") {
    httpd_resp_set_status(req, "200 OK");
    httpd_resp_set_type(req, "text/html; charset=utf-8");
    httpd_resp_sendstr(req,
                      "<!doctype html><html><head><meta charset=\"utf-8\"><title>AZT OTA Upgrade (HTTPS)</title></head><body>"
                      "<h1>AZT OTA Upgrade (HTTPS)</h1>"
                      "<p>POST bundle to <code>/api/v0/device/upgrade</code> on this HTTPS endpoint.</p>"
                      "</body></html>");
    return ESP_OK;
  }

  if (method == "POST" && path == "/api/v0/device/upgrade") {
    String err;
    if (xSemaphoreTake(g_state_mu, pdMS_TO_TICKS(4000)) != pdTRUE) {
      httpd_resp_set_status(req, "503 Service Unavailable");
      httpd_resp_set_type(req, "application/json");
      httpd_resp_sendstr(req, "{\"ok\":false,\"error\":\"ERR_STATE_LOCK\"}");
      return ESP_OK;
    }
    bool ok = handle_ota_upgrade_bundle_post_https(req, req->content_len, *g_state, err);
    xSemaphoreGive(g_state_mu);

    if (ok) {
      httpd_resp_set_status(req, "200 OK");
      httpd_resp_set_type(req, "application/json");
      httpd_resp_sendstr(req, "{\"ok\":true,\"upgrade_written\":true,\"reboot_required\":true,\"detail\":\"firmware accepted; run explicit reboot command to apply\"}");
      return ESP_OK;
    }

    httpd_resp_set_status(req, "400 Bad Request");
    httpd_resp_set_type(req, "application/json");
    String body = String("{\"ok\":false,\"error\":\"ERR_OTA_UPGRADE\",\"detail\":") + json_escape_for_error(err) + "}";
    httpd_resp_send(req, body.c_str(), body.length());
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
  HttpDispatchResult r = dispatch_request(method, path, body, *g_state);
  xSemaphoreGive(g_state_mu);

  String status = String(r.code) + (r.code == 200 ? " OK" : " Error");
  httpd_resp_set_status(req, status.c_str());
  httpd_resp_set_type(req, r.content_type.c_str());
  httpd_resp_send(req, r.body.c_str(), r.body.length());

  if (r.reboot_after_response) {
    vTaskDelay(pdMS_TO_TICKS(150));
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
