"""
uhashlib_hw -- the hardware accelerated hashes, on Linux.

The K210 boards have a hardware SHA-256; the MaixPy firmware asks for
it as `uhashlib_hw`.  There is no such hardware here, so this is the
software one under the name the firmware uses.
"""

from uhashlib import *  # noqa: F401,F403
from uhashlib import sha1, sha256  # noqa: F401
try:
    from uhashlib import sha512  # noqa: F401
except ImportError:
    sha512 = None  # noqa: F401


def pbkdf2_hmac_sha256(password, salt, iterations, dklen=32):
    """PBKDF2-HMAC-SHA256, pure Python on top of uhashlib."""
    if isinstance(password, str):
        password = password.encode()
    if isinstance(salt, str):
        salt = salt.encode()
    import hmac as _hmac

    def _prf(p, s):
        return _hmac.new(p, s, sha256).digest()

    blocks = (dklen + 31) // 32
    out = b""
    for i in range(1, blocks + 1):
        # U_1
        u = _prf(password, salt + i.to_bytes(4, "big"))
        t = bytearray(u)
        for _ in range(2, iterations + 1):
            u = _prf(password, u)
            for j in range(len(t)):
                t[j] ^= u[j]
        out += bytes(t)
    return out[:dklen]


# ---------------------------------------------------------------------------
# SHA-512 (pure Python) and a generic PBKDF2-HMAC, so that embit's
# hashlib.pbkdf2_hmac("sha512"/"sha256", ...) keeps working on MicroPython,
# which ships no sha512 and no pbkdf2_hmac.
# ---------------------------------------------------------------------------

import struct as _struct


def _rotr64(x, n):
    return ((x >> n) | (x << (64 - n))) & 0xFFFFFFFFFFFFFFFF


_K512 = [
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
    0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
    0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
    0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
    0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
    0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
    0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
    0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d47,
    0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
]


class sha512:
    digest_size = 64
    block_size = 128
    def __init__(self, data=b""):
        self._h = [
            0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
            0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
        ]
        self._buf = bytearray()
        self._len = 0
        if data:
            self.update(data)

    def update(self, data):
        if isinstance(data, str):
            data = data.encode()
        self._buf.extend(data)
        self._len += len(data)
        while len(self._buf) >= 128:
            self._process(self._buf[:128])
            self._buf = self._buf[128:]

    def _process(self, chunk):
        w = [0] * 80
        for i in range(16):
            w[i] = _struct.unpack_from(">Q", chunk, i * 8)[0]
        for i in range(16, 80):
            s0 = _rotr64(w[i - 15], 1) ^ _rotr64(w[i - 15], 8) ^ (w[i - 15] >> 7)
            s1 = _rotr64(w[i - 2], 19) ^ _rotr64(w[i - 2], 61) ^ (w[i - 2] >> 6)
            w[i] = (w[i - 16] + s0 + w[i - 7] + s1) & 0xFFFFFFFFFFFFFFFF

        a, b, c, d, e, f, g, h = self._h
        for i in range(80):
            S1 = _rotr64(e, 14) ^ _rotr64(e, 18) ^ _rotr64(e, 41)
            ch = (e & f) ^ ((~e) & g)
            t1 = (h + S1 + ch + _K512[i] + w[i]) & 0xFFFFFFFFFFFFFFFF
            S0 = _rotr64(a, 28) ^ _rotr64(a, 34) ^ _rotr64(a, 39)
            maj = (a & b) ^ (a & c) ^ (b & c)
            t2 = (S0 + maj) & 0xFFFFFFFFFFFFFFFF
            h = g; g = f; f = e
            e = (d + t1) & 0xFFFFFFFFFFFFFFFF
            d = c; c = b; b = a
            a = (t1 + t2) & 0xFFFFFFFFFFFFFFFF
        for i, v in enumerate((a, b, c, d, e, f, g, h)):
            self._h[i] = (self._h[i] + v) & 0xFFFFFFFFFFFFFFFF

    def digest(self):
        # padding
        buf = bytearray(self._buf)
        total = self._len
        buf.append(0x80)
        while (len(buf) + 16) % 128 != 0:
            buf.append(0)
        buf += _struct.pack(">Q", total * 8)
        # process remaining
        saved = self._buf
        saved_len = self._len
        self._buf = buf
        self._len = len(buf)
        # process all 128-byte blocks
        off = 0
        while off + 128 <= len(buf):
            self._process(buf[off:off + 128])
            off += 128
        self._buf = saved
        self._len = saved_len
        return b"".join(_struct.pack(">Q", h) for h in self._h)

    def hexdigest(self):
        return self.digest().hex()


def pbkdf2_hmac(hash_name, password, salt, iterations, dklen=None):
    """Generic PBKDF2-HMAC on top of hashlib's hash factory."""
    if isinstance(password, str):
        password = password.encode()
    if isinstance(salt, str):
        salt = salt.encode()
    if dklen is None:
        dklen = {"sha1": 20, "sha256": 32, "sha512": 64}.get(hash_name, 32)
    # resolve the hash factory
    if hash_name == "sha512":
        factory = sha512
    elif hash_name == "sha256":
        factory = sha256
    elif hash_name == "sha1":
        factory = sha1
    else:
        import hashlib as _hl
        factory = lambda d=b"": _hl.new(hash_name, d)

    def _prf(p, s):
        h = factory()
        # HMAC
        block_size = 128 if hash_name == "sha512" else 64
        if len(p) > block_size:
            p = factory(p).digest()
        p = p + b"\x00" * (block_size - len(p))
        ipad = bytes(b ^ 0x36 for b in p)
        opad = bytes(b ^ 0x5C for b in p)
        inner = factory()
        inner.update(ipad)
        inner.update(s)
        outer = factory()
        outer.update(opad)
        outer.update(inner.digest())
        return outer.digest()

    blocks = (dklen + factory().digest_size - 1) // factory().digest_size
    out = b""
    for i in range(1, blocks + 1):
        u = _prf(password, salt + _struct.pack(">I", i))
        t = bytearray(u)
        for _ in range(2, iterations + 1):
            u = _prf(password, u)
            for j in range(len(t)):
                t[j] ^= u[j]
        out += bytes(t)
    return out[:dklen]

# ---------------------------------------------------------------------------
# Inject a replacement `hashlib` module into sys.modules, because MicroPython's
# builtin hashlib is immutable (setattr raises).  embit imports `hashlib` and
# needs sha512 + pbkdf2_hmac, which the builtin lacks.
# ---------------------------------------------------------------------------
try:
    import sys as _sys
    import uhashlib as _uh

    class _HashLib:
        pass

    _hl = _HashLib()
    for _name in ("md5", "sha1", "sha256"):
        if hasattr(_uh, _name):
            setattr(_hl, _name, getattr(_uh, _name))

    _hl.sha512 = sha512
    _hl.pbkdf2_hmac = pbkdf2_hmac

    def _new(name, data=b""):
        if name == "sha512":
            return sha512(data)
        if name == "sha256":
            return _uh.sha256(data)
        if name == "sha1":
            return _uh.sha1(data)
        if name == "md5":
            return _uh.md5(data)
        raise ValueError(name)

    _hl.new = _new
    _sys.modules["hashlib"] = _hl
except Exception:
    pass
