#include <cassert>
#include "azt_stream_limits.h"

int main() {
  using namespace azt;
  static_assert(kMaxStreamDurationUs == 94608000000000ULL, "three 365-day years");
  assert(!stream_limit_reached(0, 1));
  assert(!stream_limit_reached(kMaxStreamDurationUs - 1, 1));
  assert(stream_limit_reached(kMaxStreamDurationUs, 1));
  assert(stream_limit_reached(kMaxStreamDurationUs + 1, 1));
  assert(!stream_limit_reached(0, UINT32_MAX - 3));
  assert(stream_limit_reached(0, UINT32_MAX - 2));
  assert(stream_limit_reached(0, UINT32_MAX));
}
