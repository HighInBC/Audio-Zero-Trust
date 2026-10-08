#pragma once

#include <cstdint>

namespace azt {

// Three fixed 365-day years, measured with the monotonic clock, not NTP.
constexpr uint64_t kMaxStreamDurationUs = 3ULL * 365 * 24 * 60 * 60 * 1000000;
// Leave the final two sequence numbers for the close message and finalizer.
constexpr uint32_t kMaxStreamDataSequence = UINT32_MAX - 2;

inline bool stream_limit_reached(uint64_t elapsed_us, uint32_t sequence) {
  return elapsed_us >= kMaxStreamDurationUs || sequence >= kMaxStreamDataSequence;
}

}  // namespace azt
