#pragma once

#include <Arduino.h>

#include <vector>

namespace azt_test {

struct Context {
  String* pubkey_pem = nullptr;
};

struct TestCase {
  const char* name;
  bool (*fn)(Context&);
  const char* fail_detail;
};

using Registry = std::vector<TestCase>;

void register_test_azt_crypto(Registry& out);
void register_test_azt_stream(Registry& out);
void register_test_azt_discovery(Registry& out);
void register_test_azt_http_api(Registry& out);
void register_test_azt_config(Registry& out);

}  // namespace azt_test
