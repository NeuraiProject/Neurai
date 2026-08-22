# Independent check of the DePIN protocol-2 constructions documented in
# doc/depin-messaging-protocol.md, against vectors produced by a regtest node.
import hashlib, base64, struct, sys, json
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# --- secp256k1 (pure python, enough for ECDH, recovery, verify) ---
P  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G  = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
      0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)
def inv(a, m=P): return pow(a, m-2, m)
def add(p, q):
    if p is None: return q
    if q is None: return p
    if p[0] == q[0] and (p[1] + q[1]) % P == 0: return None
    if p == q: l = (3*p[0]*p[0]) * inv(2*p[1]) % P
    else:      l = (q[1]-p[1]) * inv(q[0]-p[0]) % P
    x = (l*l - p[0] - q[0]) % P
    return (x, (l*(p[0]-x) - p[1]) % P)
def mul(k, p):
    r = None
    while k:
        if k & 1: r = add(r, p)
        p = add(p, p); k >>= 1
    return r
def compress(pt): return bytes([2 + (pt[1] & 1)]) + pt[0].to_bytes(32, 'big')
def decompress(b):
    x = int.from_bytes(b[1:], 'big'); y2 = (x**3 + 7) % P; y = pow(y2, (P+1)//4, P)
    if (y & 1) != (b[0] & 1): y = P - y
    return (x, y)
def sha256(b): return hashlib.sha256(b).digest()
def sha256d(b): return sha256(sha256(b))
def hash160(b): return hashlib.new('ripemd160', sha256(b)).digest()

# --- Bitcoin-style serialization ---
def compact(n):
    if n < 253: return bytes([n])
    if n <= 0xFFFF: return b'\xfd' + n.to_bytes(2, 'little')
    return b'\xfe' + n.to_bytes(4, 'little')
def ser_bytes(b): return compact(len(b)) + b
def ser_str(s): return ser_bytes(s.encode())
def read_compact(b, i):
    if b[i] < 253: return b[i], i+1
    if b[i] == 0xfd: return int.from_bytes(b[i+1:i+3], 'little'), i+3
    return int.from_bytes(b[i+1:i+5], 'little'), i+5
def read_bytes(b, i):
    n, i = read_compact(b, i); return b[i:i+n], i+n

# --- message signing (signmessage-compatible, recoverable) ---
MAGIC = "Neurai Signed Message:\n"
def msghash(text): return sha256d(ser_str(MAGIC) + ser_str(text))
def recover(sig65, h):
    hdr, r, s = sig65[0], int.from_bytes(sig65[1:33], 'big'), int.from_bytes(sig65[33:], 'big')
    recid = (hdr - 27) & 3
    x = r + (recid >> 1) * N
    y = pow((x**3 + 7) % P, (P+1)//4, P)
    if (y & 1) != (recid & 1): y = P - y
    R = (x, y); e = int.from_bytes(h, 'big')
    Q = mul(inv(r, N), add(mul(s, R), mul((-e) % N, G)))
    return compress(Q)
def verify_der(pub, h, der):
    # minimal DER parse
    assert der[0] == 0x30; i = 2
    assert der[i] == 2; l = der[i+1]; r = int.from_bytes(der[i+2:i+2+l], 'big'); i += 2+l
    assert der[i] == 2; l = der[i+1]; s = int.from_bytes(der[i+2:i+2+l], 'big')
    e = int.from_bytes(h, 'big'); w = inv(s, N)
    Qp = decompress(pub)
    pt = add(mul(e*w % N, G), mul(r*w % N, Qp))
    return pt is not None and pt[0] % N == r

# --- ECIES ---
def ecdh(d, Qbytes):
    pt = mul(d, decompress(Qbytes)); return sha256(compress(pt))   # libsecp256k1 default
def kdf(secret, n=32):
    out = b''; c = 1
    while len(out) < n: out += sha256(secret + struct.pack('>I', c)); c += 1
    return out[:n]
def parse_ecies(b):
    i = 0
    eph, i = read_bytes(b, i); payload, i = read_bytes(b, i)
    cnt, i = read_compact(b, i); rk = {}
    for _ in range(cnt):
        key = b[i:i+20]; i += 20; val, i = read_bytes(b, i); rk[key] = val
    assert i == len(b), "trailing bytes"
    return eph, payload, rk
def ecies_decrypt(hexmsg, d, pub):
    eph, payload, rk = parse_ecies(bytes.fromhex(hexmsg))
    entry = rk[hash160(pub)]
    W = kdf(ecdh(d, eph))
    K = AESGCM(W).decrypt(entry[:12], entry[12:], None)      # ct||tag, no AAD
    assert len(K) == 32
    return AESGCM(K).decrypt(payload[:12], payload[12:], None).decode()

def wif_to_priv(wif):
    raw = b58decode(wif); assert sha256d(raw[:-4])[:4] == raw[-4:]
    body = raw[1:-4]; assert len(body) == 33 and body[-1] == 1  # compressed
    return int.from_bytes(body[:32], 'big')
B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
def b58decode(s):
    n = 0
    for ch in s: n = n*58 + B58.index(ch)
    out = n.to_bytes((n.bit_length()+7)//8, 'big')
    return b'\x00' * (len(s) - len(s.lstrip('1'))) + out
def addr_payload(addr): raw = b58decode(addr); return raw[1:-4]

V = {}
for line in open(sys.argv[1]):
    if '=' in line and not line.startswith('='): k, v = line.rstrip('\n').split('=', 1); V[k] = v

d = wif_to_priv(V['holder_wif']); pub = compress(mul(d, G))
assert pub.hex() == V['holder_pubkey'], "WIF -> pubkey"
assert hash160(pub) == addr_payload(V['holder_address']), "pubkey -> address payload"
print("ok  WIF/pubkey/address")

for pre, sig in (('req_preimage', 'req_signature'), ('get_preimage', 'get_signature')):
    assert recover(base64.b64decode(V[sig]), msghash(V[pre])) == pub, pre
print("ok  signmessage-compatible recoverable signatures (DEPIN-REQ, DEPIN-GET)")

poolpub = bytes.fromhex(V['pool_pubkey'])
assert hash160(poolpub) == addr_payload(V['pool_address'])
def check_poolsig(method, token, address, nonce, body, sig):
    pre = f"DEPIN-RESP|{method}|{token}|{address}|{nonce}|{sha256(body.encode()).hex()}"
    assert recover(base64.b64decode(sig), msghash(pre)) == poolpub, method
check_poolsig('depingetmsginfo', '&TEST', '', '', V['info_body'], V['info_poolsig'])
info = json.loads(bytes.fromhex(V['info_body']).decode()); assert info['protocol'] == 2 and info['depinpoolpkey'] == V['pool_pubkey']
check_poolsig('depinchallenge', '&TEST/SEC', V['holder_address'], '', V['challenge_encrypted'], V['challenge_poolsig'])
check_poolsig('depinreceivemsg', '&TEST/SEC', V['holder_address'], V['receive_nonce'], V['receive_encrypted'], V['receive_poolsig'])
print("ok  poolsig preimage and recovery (plain body, challenge, receivemsg)")

assert ecies_decrypt(V['challenge_encrypted'], d, pub) == V['challenge_plain']
assert ecies_decrypt(V['receive_encrypted'], d, pub) == V['receive_plain']
print("ok  ECIES envelope: ECDH(sha256 of compressed point) -> KDF -> AES-256-GCM, two layers")

if 'receive2_plain' in V:
    check_poolsig('depinreceivemsg', '&TEST/SEC', V['holder_address'], V['receive2_nonce'], V['receive2_encrypted'], V['receive2_poolsig'])
    plain = ecies_decrypt(V['receive2_encrypted'], d, pub); assert plain == V['receive2_plain']
    m = json.loads(plain)['messages'][0]
    mt = {'private': 1, 'group': 2}[m['message_type']]
    ser = ser_str(m['token']) + ser_str(m['sender']) + struct.pack('<q', m['timestamp']) + bytes([mt]) + ser_bytes(bytes.fromhex(m['encrypted_payload_hex']))
    digest = sha256d(ser)
    assert digest[::-1].hex() == m['hash'], "message hash = reversed sha256d of serialization"
    assert verify_der(bytes.fromhex(V['sender_pubkey']), digest, bytes.fromhex(m['signature_hex'])), "DER signature over digest"
    content = ecies_decrypt(m['encrypted_payload_hex'], d, pub)
    assert content == "Hello from the spec", content
    print("ok  CDepinMessage: hash, DER signature, content decryption ->", repr(content))

# --- negative vectors (spec §13.7): every one of these MUST be rejected ---
def rejected(fn):
    try:
        return not fn()
    except Exception:
        return True
def poolsig_ok(method, token, address, nonce, body, sig):
    pre = f"DEPIN-RESP|{method}|{token}|{address}|{nonce}|{sha256(body.encode()).hex()}"
    return recover(base64.b64decode(sig), msghash(pre)) == poolpub
def xor_hex(h, pos, mask=1):
    b = bytearray(bytes.fromhex(h)); b[pos] ^= mask; return b.hex()

# N1 tampered poolsig
sigb = bytearray(base64.b64decode(V['info_poolsig'])); sigb[40] ^= 1
assert rejected(lambda: poolsig_ok('depingetmsginfo', '&TEST', '', '', V['info_body'], base64.b64encode(bytes(sigb)).decode())), "N1"
# N2 re-serialized body
reser = json.dumps(info, sort_keys=True, separators=(",", ":")).encode().hex()
assert reser != V['info_body'] and rejected(lambda: poolsig_ok('depingetmsginfo', '&TEST', '', '', reser, V['info_poolsig'])), "N2"
# N3 outer GCM tag
enc = V['challenge_encrypted']
assert rejected(lambda: ecies_decrypt(xor_hex(enc, len(bytes.fromhex(enc)) - 1), d, pub)), "N3"
# N4 recipient entry tag: locate the holder's entry and flip its last byte
raw = bytes.fromhex(enc); i = 0
_, i = read_bytes(raw, i); _, i = read_bytes(raw, i); cnt, i = read_compact(raw, i)
pos = None
for _ in range(cnt):
    key = raw[i:i+20]; i += 20; n, j = read_compact(raw, i); i = j + n
    if key == hash160(pub): pos = i - 1
assert pos is not None and rejected(lambda: ecies_decrypt(xor_hex(enc, pos), d, pub)), "N4"
# N5 wrong recipient (sender key is not ours, but absence of an entry is decided by the address alone)
assert rejected(lambda: ecies_decrypt(enc, 12345, bytes.fromhex(V['sender_pubkey']))), "N5"
if 'receive2_plain' in V:
    # N6 DER signature tampered
    assert rejected(lambda: verify_der(bytes.fromhex(V['sender_pubkey']), digest, bytes.fromhex(xor_hex(m['signature_hex'], len(bytes.fromhex(m['signature_hex'])) - 1)))), "N6"
    # N7 field changed: hash and signature both fail
    ser2 = ser_str(m['token']) + ser_str(m['sender']) + struct.pack('<q', m['timestamp'] + 1) + bytes([mt]) + ser_bytes(bytes.fromhex(m['encrypted_payload_hex']))
    d2 = sha256d(ser2)
    assert d2[::-1].hex() != m['hash'] and rejected(lambda: verify_der(bytes.fromhex(V['sender_pubkey']), d2, bytes.fromhex(m['signature_hex']))), "N7"
# N8 reply bound to its challenge: receivemsg poolsig with the challenge preimage
assert rejected(lambda: poolsig_ok('depinreceivemsg', '&TEST/SEC', V['holder_address'], '', V['receive_encrypted'], V['receive_poolsig'])), "N8"
print("ok  negative vectors N1-N8 rejected (tampered poolsig, re-serialized body, GCM tags, wrong recipient, DER, field change, challenge binding)")
print("ALL VECTORS VERIFIED")
