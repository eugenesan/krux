"""The SeedKeeper applet's secure channel.

The card refuses every command except GET_STATUS, INIT_SECURE_CHANNEL (0x81)
and PROCESS_SECURE_CHANNEL (0x82) while ``needs_secure_channel`` is set.  This
implements the handshake and the encrypted envelope the applet expects:

* secp256k1 ephemeral key exchange (the applet uses Secp256k1, not P-256)
* HMAC-SHA1 key derivation: ``sc_key`` -> 16-byte AES key, ``sc_mac`` -> MAC key
* AES-128-CBC with PKCS#7 padding
* IVs made of 12 random bytes and an odd 32-bit counter; the applet uses the
  even counters for its responses, so the two directions never reuse an IV

The card returns its ephemeral public X coordinate followed by a self-signature
over ``00 20 || X``.  The Y coordinate is recovered from that signature, which
also authenticates the card's ephemeral key.
"""

import hashlib
import hmac

import urandom
from embit.util import key as _ec

CLA = 0xB0
INS_INIT_SECURE_CHANNEL = 0x81
INS_PROCESS_SECURE_CHANNEL = 0x82
INS_GET_STATUS = 0x3C

SC_EXEMPT = (0xA4, INS_INIT_SECURE_CHANNEL, INS_PROCESS_SECURE_CHANNEL, 0xFF, 0x3C)

_ORDER = _ec.SECP256K1_ORDER
_CURVE = _ec.SECP256K1
_G = _ec.SECP256K1_G


class SecureChannelError(Exception):
    """The handshake or an encrypted exchange was malformed."""


def _random_bytes(count):
    out = bytearray()
    while len(out) < count:
        out.extend(urandom.getrandbits(32).to_bytes(4, "big"))
    return bytes(out[:count])


def _aes_cbc(key, iv, data, decrypt=False):
    import ucryptolib

    cipher = ucryptolib.aes(key, ucryptolib.MODE_CBC, iv)
    if decrypt:
        return cipher.decrypt(data)
    return cipher.encrypt(data)


def _pad(data):
    pad = 16 - (len(data) % 16)
    return data + bytes([pad]) * pad


def _unpad(data):
    if not data:
        return data
    pad = data[-1]
    if pad < 1 or pad > 16 or data[-pad:] != bytes([pad]) * pad:
        raise SecureChannelError("bad padding in secure-channel response")
    return data[:-pad]


def _pubkey_from_priv(priv):
    scalar = int.from_bytes(priv, "big")
    point = _CURVE.affine(_CURVE.mul([(_G, scalar)]))
    if point is None:
        raise SecureChannelError("invalid ephemeral key")
    return b"\x04" + point[0].to_bytes(32, "big") + point[1].to_bytes(32, "big")


def _ecdh_x(priv, peer_pubkey):
    if len(peer_pubkey) != 65 or peer_pubkey[0] != 0x04:
        raise SecureChannelError("bad peer public key")
    point = (
        int.from_bytes(peer_pubkey[1:33], "big"),
        int.from_bytes(peer_pubkey[33:65], "big"),
        1,
    )
    if not _CURVE.on_curve(point):
        raise SecureChannelError("peer public key is not on secp256k1")
    shared = _CURVE.affine(_CURVE.mul([(point, int.from_bytes(priv, "big"))]))
    if shared is None:
        raise SecureChannelError("ECDH produced the point at infinity")
    return shared[0].to_bytes(32, "big")


def _der_rs(sig):
    """Return (r, s) from a DER or raw 64-byte ECDSA signature."""
    if len(sig) == 64:
        return int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big")
    if len(sig) < 8 or sig[0] != 0x30 or sig[2] != 0x02:
        raise SecureChannelError("bad ECDSA signature")
    rlen = sig[3]
    if rlen < 1 or 4 + rlen + 2 > len(sig) or sig[4 + rlen] != 0x02:
        raise SecureChannelError("bad ECDSA signature")
    slen = sig[5 + rlen]
    if 6 + rlen + slen > len(sig):
        raise SecureChannelError("bad ECDSA signature")
    return (
        int.from_bytes(sig[4 : 4 + rlen], "big"),
        int.from_bytes(sig[6 + rlen : 6 + rlen + slen], "big"),
    )


def _recover_peer_pubkey(response):
    """Parse the 0x81 response and recover the card's ephemeral public key.

    The applet sends only X plus a self-signature over ``00 20 || X``.  We do
    the ECDSA public-key recovery directly on embit's curve arithmetic: the
    platform's ``ecdsa_recover`` helper would also work in principle, but it
    goes through a DER serializer that needs ``int.bit_length()``, which this
    MicroPython port does not provide.
    """
    if len(response) < 6:
        raise SecureChannelError("secure-channel response is too short")
    x_size = (response[0] << 8) | response[1]
    if x_size != 32 or len(response) < 2 + x_size + 2:
        raise SecureChannelError("bad secure-channel public key length")
    x_bytes = response[2 : 2 + x_size]
    msg = response[: 2 + x_size]
    sig_size = (response[2 + x_size] << 8) | response[3 + x_size]
    sig_start = 4 + x_size
    if sig_size == 0 or len(response) < sig_start + sig_size:
        raise SecureChannelError("secure-channel signature is missing")
    r, s = _der_rs(response[sig_start : sig_start + sig_size])
    z = int.from_bytes(hashlib.sha256(msg).digest(), "big")
    p = _CURVE.p

    # recid 0/1 use x = r; recid 2/3 use x = r + order, which is only a
    # valid field element for a small fraction of signatures.
    for recid in range(4):
        rx = r + (_ORDER if recid >= 2 else 0)
        if rx >= p:
            continue
        y2 = (pow(rx, 3, p) + 7) % p
        y = pow(y2, (p + 1) // 4, p)
        if (y * y) % p != y2:
            continue
        if (y & 1) != (recid & 1):
            y = p - y
        point_r = (rx, y, 1)
        if not _CURVE.on_curve(point_r):
            continue
        rinv = _ec.modinv(r, _ORDER)
        # Q = r^-1 * (s*R - z*G)
        u1 = (-z * rinv) % _ORDER
        u2 = (s * rinv) % _ORDER
        point = _CURVE.affine(
            _CURVE.add(
                _CURVE.mul([(_G, u1)]),
                _CURVE.mul([(point_r, u2)]),
            )
        )
        if point is None:
            continue
        if point[0].to_bytes(32, "big") == x_bytes:
            return b"\x04" + x_bytes + point[1].to_bytes(32, "big")
    raise SecureChannelError("could not recover the card's ephemeral key")


class SecureChannel:
    """One secure-channel session with a selected SeedKeeper applet."""

    def __init__(self, transport):
        self.transport = transport
        while True:
            priv = _random_bytes(32)
            scalar = int.from_bytes(priv, "big")
            if 1 <= scalar < _ORDER:
                break
        self.privkey = priv
        self.pubkey = _pubkey_from_priv(priv)
        self.session_key = None
        self.mac_key = None
        self.counter = 1

    def _keepalive(self):
        """Send a harmless plaintext GET_STATUS while the host computes.

        The BCM2079x drops an idle ISO-DEP link after roughly a third of a
        second.  Recovering the card's Y coordinate and doing ECDH in Python
        can take that long, so the link is given traffic between the expensive
        steps; otherwise the first 0x82 after the handshake is answered with
        an RF timeout (B2).
        """
        _, sw1, sw2 = self.transport.transmit(
            bytes([CLA, INS_GET_STATUS, 0x00, 0x00])
        )
        if sw1 != 0x90 or sw2 != 0x00:
            raise SecureChannelError(
                "secure-channel keepalive failed (%02x%02x)" % (sw1, sw2)
            )

    def initiate(self):
        apdu = bytes([CLA, INS_INIT_SECURE_CHANNEL, 0x00, 0x00, len(self.pubkey)])
        apdu += self.pubkey
        response, sw1, sw2 = self.transport.transmit(apdu)
        if sw1 != 0x90 or sw2 != 0x00:
            raise SecureChannelError(
                "secure-channel handshake failed (%02x%02x)" % (sw1, sw2)
            )
        self._keepalive()
        peer = _recover_peer_pubkey(response)
        self._keepalive()
        shared = _ecdh_x(self.privkey, peer)
        self._keepalive()
        self.session_key = hmac.new(shared, b"sc_key", hashlib.sha1).digest()[:16]
        self.mac_key = hmac.new(shared, b"sc_mac", hashlib.sha1).digest()

    def wrap(self, apdu):
        iv = _random_bytes(12) + self.counter.to_bytes(4, "big")
        self.counter += 2
        ciphertext = _aes_cbc(self.session_key, iv, _pad(bytes(apdu)))
        mac = hmac.new(
            self.mac_key,
            iv + len(ciphertext).to_bytes(2, "big") + ciphertext,
            hashlib.sha1,
        ).digest()
        data = iv + len(ciphertext).to_bytes(2, "big") + ciphertext
        data += len(mac).to_bytes(2, "big") + mac
        return bytes([CLA, INS_PROCESS_SECURE_CHANNEL, 0x00, 0x00, len(data)]) + data

    def unwrap(self, data):
        if not data:
            return b""
        if len(data) < 18:
            raise SecureChannelError("encrypted response is too short")
        iv = data[:16]
        size = (data[16] << 8) | data[17]
        ciphertext = data[18:]
        if len(ciphertext) != size:
            raise SecureChannelError("encrypted response has the wrong length")
        return _unpad(_aes_cbc(self.session_key, iv, ciphertext, decrypt=True))
