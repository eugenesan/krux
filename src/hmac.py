"""
hmac -- the keyed hashing, in pure Python.

MicroPython's unix port has no `hmac` module, and the firmware's
`embit` needs it (it signs the PSBTs).  HMAC is a small amount of
code on top of `hashlib`, so here it is.

Only what `embit` uses is provided: `new(key, msg=None, digestmod=None)`
and `HMAC(key, msg=None, digestmod=None)`, with `update`, `digest`,
`hexdigest` and `copy`.
"""

import hashlib


def _digest_size(digestmod):
    name = digestmod()
    return name.digest_size


class HMAC:
    """The keyed hashing (RFC 2104)."""

    def __init__(self, key, msg=None, digestmod=None):
        # embit passes the hash as a name ("sha256", "sha512", ...)
        if isinstance(digestmod, str):
            name = digestmod
            try:
                import uhashlib_hw
                if name == "sha512":
                    digestmod = uhashlib_hw.sha512
                elif name == "sha256":
                    digestmod = uhashlib_hw.sha256 if hasattr(uhashlib_hw, "sha256") else hashlib.sha256
                elif name == "sha1":
                    digestmod = hashlib.sha1
                else:
                    digestmod = getattr(hashlib, name)
            except Exception:
                digestmod = getattr(hashlib, name, hashlib.sha256)
        if digestmod is None:
            digestmod = hashlib.sha256

        self.digestmod = digestmod
        # sha512 uses 128-byte blocks
        try:
            self.block_size = 128 if getattr(digestmod, "block_size", 64) == 128 or digestmod in (uhashlib_hw.sha512,) else 64
        except Exception:
            self.block_size = 64
        self._outer = self._inner = None
        self._fed = bytearray()

        if isinstance(key, str):
            key = key.encode()
        if len(key) > self.block_size:
            key = digestmod(key).digest()
        key = key + b"\x00" * (self.block_size - len(key))

        self._key = key
        self._ipad = bytes(b ^ 0x36 for b in key)
        self._opad = bytes(b ^ 0x5C for b in key)

        self._inner = digestmod(self._ipad)
        if msg is not None:
            self.update(msg)

    def update(self, msg):
        if isinstance(msg, str):
            msg = msg.encode()
        self._fed.extend(msg)
        self._inner.update(msg)

    def digest(self):
        inner = self._inner.digest()
        outer = self.digestmod(self._opad)
        outer.update(inner)
        return outer.digest()

    def hexdigest(self):
        digest = self.digest()
        if not isinstance(digest, str):
            digest = "".join("%02x" % b for b in digest)
        return digest

    def copy(self):
        other = HMAC.__new__(HMAC)
        other.digestmod = self.digestmod
        other.block_size = self.block_size
        other._key = self._key
        other._ipad = self._ipad
        other._opad = self._opad
        other._fed = bytearray(self._fed)
        other._inner = self.digestmod(self._ipad)
        other._inner.update(bytes(self._fed))
        return other


def new(key, msg=None, digestmod=None):
    """A new keyed hashing object."""
    return HMAC(key, msg, digestmod)
