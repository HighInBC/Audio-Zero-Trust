#pragma once

#include <Arduino.h>
#include <Preferences.h>

namespace azt {

// Robust string persistence for NVS-backed Preferences.
// Automatically chunks large values across multiple keys.
bool kv_set_string(Preferences& prefs, const char* key, const String& value);
String kv_get_string(Preferences& prefs, const char* key, const String& default_value = "");
void kv_remove_key(Preferences& prefs, const char* key);

}  // namespace azt
