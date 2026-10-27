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
