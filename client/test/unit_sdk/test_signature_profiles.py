"""Independent synthetic AZT fixtures exercise both signing profiles and recovery evidence."""
import base64
import hashlib
import json
import struct
import wave
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from tools.azt_client.signatures import stream_signing_key
from tools.azt_client.stream import validate_azt1_stream_chain, decode_azt1_stream_to_wav, LiveAzt1PcmDecoder

b64 = lambda b: base64.b64encode(b).decode()
sha = lambda b: hashlib.sha256(b).digest()
pack = lambda n: struct.pack('>I', n)
FIXTURES = Path(__file__).parent / 'fixtures' / 'signature_profiles'


def build_fixture(algorithm, *, finalization_profile=None, inner_profile_override=None, final_domain_override=None, vectors=None):
    """Used only to create golden files, never during tests. No production keys/audio."""
    key = ed25519.Ed25519PrivateKey.generate() if algorithm == 'ed25519' else rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw) if algorithm == 'ed25519' else key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    def sign(message):
        return key.sign(message) if algorithm == 'ed25519' else key.sign(message, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32), hashes.SHA256())
    common = dict(chain_alg='sha256-link', chain_domain='AZT1-CHAIN-V1-NONCE', chain_root_mode='genesis-signature-block', block1_must_be_signature_ref_seq0=True,
                  chunk_record_format='seq_u32be|block_flags_type_u8|body_len_u32be|tag_len_u8|body|tag|chain_v32', block_type_encoding='msb_encryption_flag_v1', block_type_encrypted_mask=128, block_type_id_mask=127,
                  audio_frame_duration_ms=20, pcm_blocks_are_single_frame=True, signature_checkpoint_alg=algorithm)
    if finalization_profile is not None:
        common.update(finalize_signature_profile=finalization_profile, finalize_signature_domain='AZT1FINAL1||ref_seq_u32be||chain_v32')
    inner = dict(common, audio_key_b64=b64(bytes(range(32))), audio_nonce_prefix_b64=b64(b'1234'), chain_genesis_secret_b64=b64(b'g'*32), device_sign_public_key_b64=b64(public), device_sign_fingerprint_hex=sha(public).hex(), audio_format='pcm_s16le', sample_rate_hz=16000, channels=1, sample_width_bytes=2, audio_cipher='aes-256-gcm-mixed-blocks-sha256-chain', recommended_decode_gain=1)
    if inner_profile_override is not None:
        if inner_profile_override == 'absent':
            inner.pop('finalize_signature_profile', None);inner.pop('finalize_signature_domain', None)
        else:
            inner['finalize_signature_profile'] = inner_profile_override
    inner_bytes = json.dumps(inner, separators=(',', ':')).encode()
    recipient = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    recipient_der = recipient.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    header_key, header_nonce = b'h'*32, b'n'*12
    encrypted = AESGCM(header_key).encrypt(header_nonce, inner_bytes, None)
    outer = dict(common, version=0, container_major=0, container_minor=int(algorithm != 'ed25519'), stream_auth_nonce='golden-synthetic-test-only',
                 this_header_signature_alg=algorithm, this_header_signing_key_b64=b64(public), this_header_signing_key_fingerprint_hex=sha(public).hex(),
                 this_header_signing_key_fingerprint_alg='sha256-raw-ed25519-pub' if algorithm == 'ed25519' else 'sha256-spki-der',
                 next_header_plaintext_hash_alg='sha256', next_header_plaintext_sha256_b64=b64(sha(inner_bytes)),
                 next_header_key_wrap='rsa-oaep-sha256', next_header_cipher='aes-256-gcm', next_header_aad_mode='none',
                 next_header_recipient_key_fingerprint_alg='sha256-spki-der', next_header_recipient_key_fingerprint_hex=sha(recipient_der).hex(),
                 next_header_ciphertext_hash_alg='sha256', next_header_ciphertext_sha256_b64=b64(sha(encrypted[:-16])), next_header_ciphertext_len=len(encrypted)-16,
                 next_header_nonce_b64=b64(header_nonce), next_header_tag_b64=b64(encrypted[-16:]),
                 next_header_wrapped_key_b64=b64(recipient.public_key().encrypt(header_key, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))),
                 estimated_frames_formula='COUNT(block_type=0) + SUM(block_type=2.missed_frames_u16be)', estimated_duration_ms_formula='(COUNT(block_type=0) + SUM(block_type=2.missed_frames_u16be)) * audio_frame_duration_ms')
    outer_bytes = json.dumps(outer, separators=(',', ':')).encode()
    prefix = b'AZT1\n' + outer_bytes + b'\n' + b64(sign(outer_bytes)).encode() + b'\n'
    encrypted_prefix = prefix + struct.pack('>H', len(encrypted)-16) + encrypted[:-16]
    decoded_prefix = prefix + b'\xff\xff' + inner_bytes + b'\n'
    records, previous = [], b''
    for seq, kind in enumerate((1, 0, 1, 0, 127), 1):
        tag = b''
        if kind == 0:
            wire = 128
            data = AESGCM(bytes(range(32))).encrypt(b'1234'+pack(seq)+b'\0'*4, bytes(range(256))*2 + bytes(range(128)), None)
            body, tag = data[:-16], data[-16:]
        else:
            wire = kind
            domain = (final_domain_override or (b'AZT1FINAL1' if finalization_profile == 'azt-finalize-v1' else b'AZT1SIG1')) if kind == 127 else b'AZT1SIG1'
            message = b'AZT1SIG0'+b'g'*32 if seq == 1 else domain+pack(seq-1)+previous
            body = pack(seq-1)+sign(message)
        core = pack(seq)+bytes([wire])+pack(len(body))+bytes([len(tag)])+body+tag
        chain_input = b'AZT1-CHAIN-V1-NONCE'+sha(outer['stream_auth_nonce'].encode())+previous+core
        previous = sha(chain_input)
        if vectors is not None:
            vectors.append(dict(seq=seq, type=kind, core_hex=core.hex(), chain_input_hex=chain_input.hex(), chain_hex=previous.hex(),
                signature_message_hex=message.hex() if kind in (1,127) else None,
                signature_b64=b64(body[4:]) if kind in (1,127) else None,
                nonce_hex=(b'1234'+pack(seq)+b'\0'*4).hex() if kind==0 else None))
        records.append(core+previous)
    private = recipient.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    return encrypted_prefix+b''.join(records), decoded_prefix+b''.join(records), private


@pytest.fixture(params=['ed25519', 'rsa-pss-sha256'])
def golden(request):
    name = request.param
    return (FIXTURES / (name+'.azt')).read_bytes(), (FIXTURES / (name+'.decoded.azt')).read_bytes(), (FIXTURES / (name+'.test-recipient.pem')).read_bytes()


def record_offsets(data):
    off = data.index(b'\n', data.index(b'\n', 5)+1)+1
    size = struct.unpack('>H', data[off:off+2])[0]
    off += 2
    off = data.index(b'\n', off)+1 if size == 65535 else off+size
    result = []
    while off < len(data):
        result.append(off)
        off += 10 + struct.unpack('>I', data[off+5:off+9])[0] + data[off+9] + 32
    return result


def test_golden_all_readers(golden, tmp_path, monkeypatch, capsys):
    from tools import validate_azt1
    encrypted, decoded, private = golden
    for data, key in ((encrypted, private), (decoded, None)):
        result = validate_azt1_stream_chain(data, key)
        assert result['finalize_seen'] and result['last_verified_ref_seq'] == 4
        assert result['stream_sigs_verified'] == 3 and result['pcm_blocks'] == 2
        wav = tmp_path/'decoded.wav'
        decode_azt1_stream_to_wav(data=data, out_wav_path=wav, admin_private_key_pem=key)
        with wave.open(str(wav)) as reader:
            assert reader.getnframes() == 640
            assert reader.readframes(640) == (bytes(range(256))*2+bytes(range(128)))*2
        live = LiveAzt1PcmDecoder(listener_private_key_pem=key)
        chunks = []
        for off in range(0, len(data), 17):
            chunks.extend(live.feed(data[off:off+17]))
        assert b''.join(chunks) == (bytes(range(256))*2+bytes(range(128)))*2
        source = tmp_path/'source.azt'; source.write_bytes(data)
        keyfile = tmp_path/'test-only.pem'; keyfile.write_bytes(private)
        monkeypatch.setattr('sys.argv', ['validate_azt1', '--infile', str(source), '--key', str(keyfile), '--json'])
        assert validate_azt1.main() == 0, capsys.readouterr().out
    public = validate_azt1_stream_chain(encrypted)
    assert public['outer_header_signature_verified'] and public['stream_sigs_verified'] == 2


def test_crash_tail_is_preserved_and_reported(golden, tmp_path):
    data, _, key = golden
    offsets = record_offsets(data)
    for end in (offsets[3], offsets[4], offsets[4]+15, len(data)-1):
        crashed = data[:end]
        result = validate_azt1_stream_chain(crashed, key)
        assert not result['finalize_seen'] and result['last_verified_ref_seq'] == 2
        assert result['unsigned_tail_pcm_blocks'] == int(end >= offsets[4])
        assert result['unsigned_tail_bytes'] == max(0, end-offsets[4])
        wav = tmp_path/'crash.wav'
        decode_azt1_stream_to_wav(data=crashed, out_wav_path=wav, admin_private_key_pem=key)
        with wave.open(str(wav)) as reader:
            assert reader.getnframes() == 320
        assert crashed == data[:end]


def test_tampering_rejected(golden):
    data, _, key = golden
    offsets = record_offsets(data)
    changed = bytearray(data); changed[offsets[1]+10] ^= 1
    with pytest.raises(ValueError, match='ERR_CHAIN'):
        validate_azt1_stream_chain(bytes(changed), key)
    # Recompute the public chain after corrupting final signature: signature still rejects.
    changed = bytearray(data); changed[offsets[4]+14] ^= 1
    outer = json.loads(data.split(b'\n')[1])
    changed[-32:] = sha(b'AZT1-CHAIN-V1-NONCE'+sha(outer['stream_auth_nonce'].encode())+data[offsets[4]-32:offsets[4]]+changed[offsets[4]:-32])
    with pytest.raises(InvalidSignature):
        validate_azt1_stream_chain(bytes(changed), key)
    for reader in (lambda d: validate_azt1_stream_chain(d, key), lambda d: LiveAzt1PcmDecoder(listener_private_key_pem=key).feed(d)):
        with pytest.raises(ValueError, match='ERR_FINALIZE_NOT_LAST'):
            reader(data+data[offsets[4]:])


def test_explicit_profile_rejections(golden):
    outer = json.loads(golden[0].split(b'\n')[1])
    with pytest.raises(ValueError, match='ERR_UNSUPPORTED_SIGNATURE_ALG'):
        stream_signing_key(dict(outer, this_header_signature_alg='guess'))
    with pytest.raises(ValueError, match='ERR_SIGNATURE_ALG_MISMATCH'):
        stream_signing_key(dict(outer, signature_checkpoint_alg='guess'))
    with pytest.raises(ValueError, match='ERR_SIGNING_KEY_FP_MISMATCH'):
        stream_signing_key(dict(outer, this_header_signing_key_fingerprint_hex='00'*32))


if __name__ == '__main__':
    FIXTURES.mkdir(parents=True, exist_ok=True)
    for name in ('ed25519', 'rsa-pss-sha256'):
        encrypted, decoded, private = build_fixture(name)
        for suffix, contents in (('.azt', encrypted), ('.decoded.azt', decoded), ('.test-recipient.pem', private)):
            path = FIXTURES / (name+suffix)
            if path.exists():
                raise SystemExit('Refusing to overwrite golden fixture: '+str(path))
            path.write_bytes(contents)
