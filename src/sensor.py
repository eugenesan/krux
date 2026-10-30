"""
sensor -- the camera, on the hammerhead (Stage 3).

Thin client of the camd daemon.  camd owns the V4L2 state machine and
delivers QVGA frames over /data/krux/camd.sock.
"""

import socket
import time

GRAYSCALE = 0
RGB565 = 1
BGR565 = 2
YUV420 = 3
RGB888 = 4
BGR888 = 5
QVGA = 0
VGA = 1
QQVGA = 2
QQVGA2 = 3
QCIF = 4
HQVGA = 5
QVGA2 = 6
QQCIF = 7
SQCIF = 8

WIDTH = 320
HEIGHT = 240

class SensorError(Exception):
    pass

_sock = None
_camd_proc = None
_pixformat = RGB565


def _start_camd():
    # camd must be started externally (no subprocess in MicroPython).
    # Assume it is already running; just wait for the socket.
    time.sleep(1)


def _connect():
    global _sock
    if _sock is not None:
        return
    _start_camd()
    _sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    path = "/data/krux/camd.sock"
    addr = bytes([1, 0] + list(path.encode()) + [0] * (108 - len(path)))
    _sock.connect(addr)
    _sock.settimeout(5)


def reset(freq=18200000, dual_buff=False, choice=None):
    global _sock
    if _sock is not None:
        try:
            _sock.close()
        except Exception:
            pass
        _sock = None
    _connect()


def get_id():
    return 0x179


def set_pixformat(f):
    global _pixformat
    _pixformat = f


def set_framesize(f):
    pass


def set_windowing(roi):
    pass


def set_hmirror(v):
    pass


def set_vflip(v):
    pass


def skip_frames(num=10, time=0):
    for _ in range(num):
        snapshot()


def run(enable):
    pass


def snapshot():
    _connect()
    try:
        _sock.sendall(b"F")
        hdr = b""
        while len(hdr) < 32:
            chunk = _sock.recv(32 - len(hdr))
            if not chunk:
                raise SensorError("connection closed")
            hdr += chunk
        y_bytes = 320 * 240
        y = b""
        while len(y) < y_bytes:
            chunk = _sock.recv(y_bytes - len(y))
            if not chunk:
                raise SensorError("connection closed")
            y += chunk
        uv_bytes = 160 * 120 * 2
        uv = b""
        while len(uv) < uv_bytes:
            chunk = _sock.recv(uv_bytes - len(uv))
            if not chunk:
                raise SensorError("connection closed")
            uv += chunk
    except Exception as e:
        raise SensorError(str(e))
    import image
    img = image.Image.from_nv12(y + uv, 320, 240, 320, 160, 320, 240, 0)
    return img


def close():
    global _sock
    if _sock is not None:
        try:
            _sock.close()
        except Exception:
            pass
        _sock = None


def __write_reg(r, v):
    _connect()
    try:
        _sock.sendall(b"W" + bytes([(r >> 8) & 0xff, r & 0xff, v & 0xff]))
        resp = _sock.recv(2)
        if resp != b"OK":
            raise SensorError("write_reg failed: %r" % resp)
    except Exception as e:
        raise SensorError(str(e))


def set_exposure(lines):
    """Set coarse integration time (exposure) in lines."""
    __write_reg(0x0202, (lines >> 8) & 0xff)
    __write_reg(0x0203, lines & 0xff)


def set_gain(val):
    """Set analog gain (0x0020-0x01ff)."""
    __write_reg(0x0204, (val >> 8) & 0xff)
    __write_reg(0x0205, val & 0xff)


def set_exposure_gain(exposure_lines, gain_val):
    """Set both exposure and gain in one transaction."""
    _connect()
    try:
        _sock.sendall(b"E" + bytes([
            (exposure_lines >> 8) & 0xff, exposure_lines & 0xff,
            (gain_val >> 8) & 0xff, gain_val & 0xff,
        ]))
        resp = _sock.recv(2)
        if resp != b"OK":
            raise SensorError("set_exposure_gain failed: %r" % resp)
    except Exception as e:
        raise SensorError(str(e))


def set_vts(lines):
    """Set frame length (VTS) to allow longer exposure."""
    _connect()
    try:
        _sock.sendall(b"V" + bytes([(lines >> 8) & 0xff, lines & 0xff]))
        resp = _sock.recv(2)
        if resp != b"OK":
            raise SensorError("set_vts failed: %r" % resp)
    except Exception as e:
        raise SensorError(str(e))


# module-level aliases
_Camera__write_reg = __write_reg