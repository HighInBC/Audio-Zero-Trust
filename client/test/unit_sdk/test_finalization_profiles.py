"""Adversarial termination tests: relabeling, downgrade refusal and legacy evidence."""
import hashlib
import json
import struct
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidSignature
from tools.azt_client.signatures import finalize_domain, load_container_json
from tools.azt_client.stream import validate_azt1_stream_chain, decode_azt1_stream_to_wav, LiveAzt1PcmDecoder
from test_signature_profiles import build_fixture, record_offsets, FIXTURES

VECTORS = FIXTURES.parent / 'finalization_v1'


def relabel_terminal(data, record_index, new_type):
    offsets=record_offsets(data)
    start=offsets[record_index]
    end=offsets[record_index+1] if record_index+1<len(offsets) else len(data)
    outer=json.loads(data.split(b'\n')[1])
    core=bytearray(data[start:end-32]);core[4]=new_type
    previous=data[start-32:start]
    chain=hashlib.sha256(b'AZT1-CHAIN-V1-NONCE'+hashlib.sha256(outer['stream_auth_nonce'].encode()).digest()+previous+core).digest()
    return data[:start]+core+chain


def strict(data, key, tmp_path, monkeypatch, capsys):
    from tools import validate_azt1
    source=tmp_path/'test.azt';source.write_bytes(data)
    keyfile=tmp_path/'TEST-ONLY-recipient.pem';keyfile.write_bytes(key)
    monkeypatch.setattr('sys.argv',['validate_azt1','--infile',str(source),'--key',str(keyfile),'--json'])
    code=validate_azt1.main()
    return code, json.loads(capsys.readouterr().out)


@pytest.fixture(params=['ed25519','rsa-pss-sha256'])
def modern(request):
    name=request.param
    return ((VECTORS/(name+'.azt')).read_bytes(),(VECTORS/(name+'.decoded.azt')).read_bytes(),(VECTORS/(name+'.TEST-ONLY-recipient.pem')).read_bytes())


def test_new_profile_all_readers(modern,tmp_path,monkeypatch,capsys):
    encrypted,decoded,key=modern
    for data,decrypt in ((encrypted,key),(decoded,None)):
        result=validate_azt1_stream_chain(data,decrypt)
        assert result['finalization_intent_authenticated'] and result['termination_status']=='authenticated-finalize'
        out=decode_azt1_stream_to_wav(data=data,out_wav_path=tmp_path/'out.wav',admin_private_key_pem=decrypt)
        assert out['finalization_intent_authenticated']
        live=LiveAzt1PcmDecoder(listener_private_key_pem=decrypt)
        for offset in range(0,len(data),13): live.feed(data[offset:offset+13])
        assert live.finalization_info['finalization_intent_authenticated']
        code,result=strict(data,key,tmp_path,monkeypatch,capsys)
        assert code==0 and result['finalization_intent_authenticated']
    assert validate_azt1_stream_chain(encrypted)['finalization_intent_authenticated']


def test_checkpoint_relabel_attack_rejected_everywhere(modern,tmp_path,monkeypatch,capsys):
    encrypted,decoded,key=modern
    for data,decrypt in ((encrypted,key),(decoded,None)):
        forged=relabel_terminal(data,2,127)
        for reader in (lambda:validate_azt1_stream_chain(forged,decrypt),
                       lambda:decode_azt1_stream_to_wav(data=forged,out_wav_path=tmp_path/'attack.wav',admin_private_key_pem=decrypt),
                       lambda:LiveAzt1PcmDecoder(listener_private_key_pem=decrypt).feed(forged)):
            with pytest.raises(InvalidSignature): reader()
        code,result=strict(forged,key,tmp_path,monkeypatch,capsys)
        assert code!=0 and result['error']=='ERR_SIGNATURE'
    with pytest.raises(InvalidSignature): validate_azt1_stream_chain(relabel_terminal(encrypted,2,127))


def test_reverse_relabel_also_fails(modern):
    data,_,key=modern
    with pytest.raises(InvalidSignature): validate_azt1_stream_chain(relabel_terminal(data,4,1),key)


def test_legacy_finalization_never_claims_termination_intent(tmp_path,monkeypatch,capsys):
    for name in ('ed25519','rsa-pss-sha256'):
        data=(FIXTURES/(name+'.azt')).read_bytes();key=(FIXTURES/(name+'.test-recipient.pem')).read_bytes()
        for variant in (data,relabel_terminal(data,2,127)):
            result=validate_azt1_stream_chain(variant,key)
            assert result['finalize_seen'] and result['finalize_signature_verified']
            assert not result['finalization_intent_authenticated']
            assert result['termination_status']=='legacy-finalize-unbound' and result['finalization_warning']
            out=decode_azt1_stream_to_wav(data=variant,out_wav_path=tmp_path/'legacy.wav',admin_private_key_pem=key)
            assert out['last_verified_ref_seq']>0 and not out['finalization_intent_authenticated']
            live=LiveAzt1PcmDecoder(listener_private_key_pem=key);live.feed(variant)
            assert not live.finalization_info['finalization_intent_authenticated']
            code,result=strict(variant,key,tmp_path,monkeypatch,capsys)
            assert code==0 and result['termination_status']=='legacy-finalize-unbound'


@pytest.mark.parametrize('kwargs,error',[
    ({'finalization_profile':'unknown'},'ERR_UNSUPPORTED_FINALIZE_PROFILE'),
    ({'finalization_profile':'azt-finalize-v1','inner_profile_override':'absent'},'ERR_FINALIZE_PROFILE_MISMATCH'),
    ({'finalization_profile':'azt-finalize-v1','inner_profile_override':'unknown'},'ERR_FINALIZE_PROFILE_MISMATCH'),
])
def test_signed_unknown_and_mismatched_profiles_rejected(kwargs,error):
    data,_,key=build_fixture('rsa-pss-sha256',**kwargs)
    with pytest.raises(ValueError,match=error): validate_azt1_stream_chain(data,key)
    with pytest.raises(ValueError,match=error): LiveAzt1PcmDecoder(listener_private_key_pem=key).feed(data)


def test_no_fallback_to_checkpoint_domain(tmp_path,monkeypatch,capsys):
    data,_,key=build_fixture('rsa-pss-sha256',finalization_profile='azt-finalize-v1',final_domain_override=b'AZT1SIG1')
    with pytest.raises(InvalidSignature): validate_azt1_stream_chain(data,key)
    with pytest.raises(InvalidSignature): LiveAzt1PcmDecoder(listener_private_key_pem=key).feed(data)
    code,result=strict(data,key,tmp_path,monkeypatch,capsys)
    assert code!=0 and result['error']=='ERR_SIGNATURE'


def test_profile_cannot_be_stripped_without_invalidating_header(modern):
    data,_,_=modern
    parts=data.split(b'\n',3);outer=json.loads(parts[1])
    outer.pop('finalize_signature_profile');outer.pop('finalize_signature_domain')
    changed=b'AZT1\n'+json.dumps(outer,separators=(',',':')).encode()+b'\n'+parts[2]+b'\n'+parts[3]
    with pytest.raises(InvalidSignature): validate_azt1_stream_chain(changed)


def test_crash_preserves_signed_prefix_without_finalization_claim(modern,tmp_path):
    data,_,key=modern;offsets=record_offsets(data)
    for end in (offsets[3],offsets[4],offsets[4]+15,len(data)-1):
        crashed=data[:end];result=validate_azt1_stream_chain(crashed,key)
        assert not result['finalize_seen'] and not result['finalization_intent_authenticated']
        assert result['last_verified_ref_seq']==2
        assert result['unsigned_tail_pcm_blocks']==int(end>=offsets[4])
        out=decode_azt1_stream_to_wav(data=crashed,out_wav_path=tmp_path/'crash.wav',admin_private_key_pem=key)
        assert not out['finalization_intent_authenticated']
        assert crashed==data[:end]


def test_ambiguous_header_json_and_partial_profile_rejected():
    with pytest.raises(ValueError,match='ERR_DUPLICATE_JSON_KEY'): load_container_json('{"finalize_signature_profile":"azt-finalize-v1","finalize_signature_profile":"legacy"}')
    with pytest.raises(ValueError,match='ERR_DUPLICATE_JSON_KEY'): load_container_json('{"nested":{"a":1,"a":2}}')
    with pytest.raises(ValueError,match='ERR_UNSUPPORTED_FINALIZE_PROFILE'): finalize_domain({'finalize_signature_domain':'AZT1FINAL1||ref_seq_u32be||chain_v32'})


if __name__=='__main__':
    VECTORS.mkdir(parents=True,exist_ok=True)
    for name in ('ed25519','rsa-pss-sha256'):
        vectors=[]
        encrypted,decoded,key=build_fixture(name,finalization_profile='azt-finalize-v1',vectors=vectors)
        for suffix,contents in (('.azt',encrypted),('.decoded.azt',decoded),('.TEST-ONLY-recipient.pem',key),('.vectors.json',json.dumps(vectors,indent=2).encode())):
            with (VECTORS/(name+suffix)).open('xb') as f:f.write(contents)
