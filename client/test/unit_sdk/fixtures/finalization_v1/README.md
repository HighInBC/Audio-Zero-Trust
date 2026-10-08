# PUBLIC SYNTHETIC TEST MATERIAL — NOT DEPLOYMENT KEYS

These fixtures use synthetic PCM and publicly known test-only AES/genesis material.
The recipient private keys here exist solely to make the vectors reproducible.
Do not use them for any real recordings. No device signing private key is included.

Each signing algorithm has:

- `.azt`: encrypted inner header and encrypted audio, with a signed finalization-v1 profile.
- `.decoded.azt`: the same records with the legacy 0xffff decoded-inner-header representation.
- `.TEST-ONLY-recipient.pem`: synthetic RSA recipient private key.
- `.vectors.json`: exact per-record core bytes, chain preimage/result, signature message,
  signature bytes and GCM nonce. Null means not applicable for that record type.

Record order is genesis, PCM, checkpoint, PCM, finalizer. PCM is 640 bytes per frame:
bytes 0..255 twice then 0..127. AES key is bytes 0..31, prefix ASCII 1234, genesis
secret ASCII g repeated 32 times. These are deliberately public test constants.
Checkpoint signatures use AZT1SIG1; finalizers use AZT1FINAL1.

Generation: `test_finalization_profiles.py` as a script (refuses to overwrite files).
Tests: `python -m pytest client/test/unit_sdk/test_finalization_profiles.py`.
Encrypted ciphertext/signatures are frozen vectors; generation uses random synthetic
RSA keys/PSS salts and is not expected to reproduce byte-identical files.
