#pragma once

#include <freertos/FreeRTOS.h>
#include <freertos/semphr.h>

#include "azt_app_state.h"

namespace azt {

bool start_https_api_server(AppState* state, SemaphoreHandle_t state_mu, uint16_t port = 8443);
void stop_https_api_server();
bool https_api_server_running();

}  // namespace azt
