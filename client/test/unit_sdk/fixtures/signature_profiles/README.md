# Synthetic signature-profile golden fixtures

These files contain two deterministic synthetic PCM frames, not microphone audio.
Each stream has genesis, PCM, checkpoint, PCM, finalize records. The `.decoded.azt`
variant exposes the same inner header using the existing 0xFFFF sentinel.

The `.test-recipient.pem` files are PUBLIC TEST FIXTURE PRIVATE KEYS. They protect
no secrets and must never be used for real recordings. Device signing private
keys were discarded. Preserve these fixtures unchanged to test future readers.

The one-time generator is `test_signature_profiles.py` run as a script; it refuses
to overwrite any fixture. Tests only read the committed fixtures.
