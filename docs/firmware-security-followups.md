# Deferred firmware observations (2026-10-07)

Separate from the finalization-domain fix, retain these for focused investigation:

- Stream-start signatures bind the nonce and device identity but not stream
  options; plaintext transport permits racing an observed authorization.
- `handle_stream_impl` starts its signer before building/sending the header.
  Those early failure returns omit `signer.stop()`, and `StreamSigner` has no
  destructor cleanup. Investigate task access to expired stack state.
- Stream shutdown and termination use shared global strings and flags across
  tasks without an evident common lock; examine races and ownership.
- Device signing keys persist in NVS and are copied into task/stack buffers.
  Review secret clearing and actual hardware storage protection separately.

These observations are from source inspection, not demonstrated device exploits;
this finalization change does not resolve them.
