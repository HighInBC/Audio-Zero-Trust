"""Sequence validation must prevent public hash-chain resets from hiding audio."""
import hashlib
import json
import struct
import wave
from pathlib import Path

import pytest

from tools.azt_client.stream import (
    LiveAzt1PcmDecoder,
    decode_azt1_stream_to_wav,
    validate_azt1_stream_chain,
)


@pytest.fixture
def recording():
    # Public synthetic test data; the recipient key is only for decryption.
    fixtures = Path(__file__).parent / 'fixtures' / 'signature_profiles'
    return tuple((fixtures / ('ed25519' + suffix)).read_bytes() for suffix in (
        '.azt', '.decoded.azt', '.test-recipient.pem',
    ))


def record_offsets(data):
    off = data.index(b'\n', data.index(b'\n', 5) + 1) + 1
    size = struct.unpack('>H', data[off:off + 2])[0]
    off += 2
    off = data.index(b'\n', off) + 1 if size == 65535 else off + size
    offsets = []
    while off < len(data):
        offsets.append(off)
        off += 10 + struct.unpack('>I', data[off + 5:off + 9])[0] + data[off + 9] + 32
    return offsets


def strict(data, key, tmp_path, monkeypatch, capsys):
    from tools import validate_azt1
    source = tmp_path / 'input.azt'
    source.write_bytes(data)
    keyfile = tmp_path / 'TEST-ONLY-recipient.pem'
    keyfile.write_bytes(key)
    monkeypatch.setattr('sys.argv', [
        'validate_azt1', '--infile', str(source), '--key', str(keyfile), '--json',
    ])
    code = validate_azt1.main()
    return code, json.loads(capsys.readouterr().out)


def frame(data, seq, body, previous=b'', kind=0):
    outer = json.loads(data.split(b'\n')[1])
    nonce_hash = hashlib.sha256(outer['stream_auth_nonce'].encode()).digest()
    core = struct.pack('>IBIB', seq, kind, len(body), 0) + body
    chain = hashlib.sha256(b'AZT1-CHAIN-V1-NONCE' + nonce_hash + previous + core).digest()
    return core + chain


def inject_audio_then_restart(data):
    """Only public bytes/hashes are needed; original signatures stay untouched."""
    start, second = record_offsets(data)[:2]
    genesis = data[start:second]
    injected = frame(data, 2, b'\x12\x34' * 320, genesis[-32:])
    return data[:start] + genesis + injected + data[start:]


@pytest.mark.parametrize('header_mode', ['encrypted', 'decoded'])
@pytest.mark.parametrize('reader', ['validate', 'wav', 'live', 'strict'])
def test_injected_audio_chain_restart_rejected(recording, header_mode, reader, tmp_path, monkeypatch, capsys):
    encrypted, decoded, key = recording
    data = encrypted if header_mode == 'encrypted' else decoded
    decrypt = key if header_mode == 'encrypted' else None
    forged = inject_audio_then_restart(data)
    if reader == 'strict':
        code, result = strict(forged, key, tmp_path, monkeypatch, capsys)
        assert code != 0 and result['error'] == 'ERR_SEQUENCE'
        return
    wav = tmp_path / 'attack.wav'
    live = LiveAzt1PcmDecoder(listener_private_key_pem=decrypt)
    with pytest.raises(ValueError, match='^ERR_SEQUENCE$'):
        if reader == 'validate':
            validate_azt1_stream_chain(forged, decrypt)
        elif reader == 'wav':
            decode_azt1_stream_to_wav(data=forged, out_wav_path=wav, admin_private_key_pem=decrypt)
        else:
            # Sequence state must persist across network chunks.
            for offset in range(0, len(forged), 13):
                live.feed(forged[offset:offset + 13])
    assert not wav.exists()


@pytest.mark.parametrize('index,seq', [(0, 0), (0, 2), (1, 0), (1, 1), (1, 3), (3, 2), (1, 0xFFFFFFFF)])
def test_nonconsecutive_sequences_rejected(recording, index, seq, tmp_path, monkeypatch, capsys):
    _, data, key = recording
    offsets = record_offsets(data)
    start = offsets[index]
    # A public, correctly hashed plaintext record isolates sequence enforcement
    # from ciphertext nonce checks and later checkpoint verification.
    previous = data[start - 32:start] if index and seq != 1 else b''
    forged = data[:start] + frame(data, seq, b'\0' * 640, previous) + data[offsets[index + 1]:]
    for read in (
        lambda: validate_azt1_stream_chain(forged),
        lambda: decode_azt1_stream_to_wav(data=forged, out_wav_path=tmp_path / 'bad.wav'),
        lambda: LiveAzt1PcmDecoder(listener_private_key_pem=None).feed(forged),
    ):
        with pytest.raises(ValueError, match='^ERR_SEQUENCE$'):
            read()
    code, result = strict(forged, key, tmp_path, monkeypatch, capsys)
    assert code != 0 and result['error'] == 'ERR_SEQUENCE'


@pytest.mark.parametrize('header_mode', ['encrypted', 'decoded'])
def test_valid_recording_still_decodes(recording, header_mode, tmp_path, monkeypatch, capsys):
    encrypted, decoded, key = recording
    data = encrypted if header_mode == 'encrypted' else decoded
    decrypt = key if header_mode == 'encrypted' else None
    expected_pcm = (bytes(range(256)) * 2 + bytes(range(128))) * 2
    assert validate_azt1_stream_chain(data, decrypt)['pcm_bytes'] == len(expected_pcm)
    wav = tmp_path / 'valid.wav'
    decode_azt1_stream_to_wav(data=data, out_wav_path=wav, admin_private_key_pem=decrypt)
    with wave.open(str(wav)) as audio:
        assert audio.readframes(audio.getnframes()) == expected_pcm
    live = LiveAzt1PcmDecoder(listener_private_key_pem=decrypt)
    pcm = []
    for offset in range(0, len(data), 13):
        pcm.extend(live.feed(data[offset:offset + 13]))
    assert b''.join(pcm) == expected_pcm
    code, result = strict(data, key, tmp_path, monkeypatch, capsys)
    assert code == 0 and result['ok']
