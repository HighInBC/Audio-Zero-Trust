#pragma once

#include <vector>

#include "azt_app_state.h"
#include "azt_stream.h"

namespace azt {

bool build_header_prefix(StreamCtx& sc,
                         const AppState& state,
                         const unsigned char sign_sk[64],
                         uint32_t sig_checkpoint_min_interval,
                         float recommended_decode_gain,
                         const String& recording_started_utc,
                         const String& stream_auth_nonce,
                         uint32_t smtp_time_since_last_sync_seconds,
                         float audio_frame_duration_ms,
                         std::vector<uint8_t>& out_prefix);

}  // namespace azt
