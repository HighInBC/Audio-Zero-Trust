#include "azt_kv_store.h"

namespace azt {
namespace {

static constexpr size_t kChunkBytes = 700;
static const char* kChunkMarkerPrefix = "@@CH:";

static bool parse_chunk_marker(const String& value, int& out_count) {
  out_count = 0;
  if (!value.startsWith(kChunkMarkerPrefix)) return false;
  String n = value.substring(strlen(kChunkMarkerPrefix));
  n.trim();
  if (n.length() == 0) return false;
  int c = n.toInt();
  if (c <= 0 || c > 256) return false;
  out_count = c;
  return true;
}

static String chunk_key(const char* key, int index) {
  String base = String(key ? key : "");
  if (base.length() > 11) base = base.substring(0, 11);
  String suffix = String(index);
  String out = base + "_" + suffix;
  if (out.length() > 15) {
    // Keep deterministic key naming within NVS 15-char key limit.
    out = out.substring(0, 15);
  }
  return out;
}

static void remove_chunk_keys(Preferences& prefs, const char* key, int count) {
  for (int i = 0; i < count; ++i) {
    prefs.remove(chunk_key(key, i).c_str());
  }
}

}  // namespace

void kv_remove_key(Preferences& prefs, const char* key) {
  String existing = prefs.getString(key, "");
  int chunk_count = 0;
  if (parse_chunk_marker(existing, chunk_count)) {
    remove_chunk_keys(prefs, key, chunk_count);
  }
  prefs.remove(key);
}

bool kv_set_string(Preferences& prefs, const char* key, const String& value) {
  kv_remove_key(prefs, key);

  if (value.length() == 0) {
    return true;
  }

  if (value.length() <= static_cast<int>(kChunkBytes)) {
    return prefs.putString(key, value) > 0;
  }

  const int total = value.length();
  const int chunks = (total + static_cast<int>(kChunkBytes) - 1) / static_cast<int>(kChunkBytes);
  for (int i = 0; i < chunks; ++i) {
    const int start = i * static_cast<int>(kChunkBytes);
    const int len = min(static_cast<int>(kChunkBytes), total - start);
    String part = value.substring(start, start + len);
    if (prefs.putString(chunk_key(key, i).c_str(), part) == 0) {
      return false;
    }
  }

  String marker = String(kChunkMarkerPrefix) + String(chunks);
  return prefs.putString(key, marker) > 0;
}

String kv_get_string(Preferences& prefs, const char* key, const String& default_value) {
  String raw = prefs.getString(key, default_value);

  int chunk_count = 0;
  if (!parse_chunk_marker(raw, chunk_count)) {
    return raw;
  }

  String out;
  for (int i = 0; i < chunk_count; ++i) {
    String part = prefs.getString(chunk_key(key, i).c_str(), "");
    if (part.length() == 0) {
      return default_value;
    }
    out += part;
  }
  return out;
}

}  // namespace azt
