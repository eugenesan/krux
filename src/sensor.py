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
_last_seq = -1
_last_snapshot_ms = 0


def _start_camd():
    # camd is started by the firmware init (or by the test harness).
    # There is no subprocess in MicroPython, so wait for its socket.
    time.sleep(0.2)


def _connect():
    global _sock
    if _sock is not None:
        return
    _start_camd()
    path = "/data/krux/camd.sock"
    addr = bytes([1, 0] + list(path.encode()) + [0] * (108 - len(path)))
    last_error = None
    for _ in range(80):
        try:
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.connect(addr)
            s.settimeout(5)
            _sock = s
            return
        except OSError as e:
            last_error = e
            time.sleep(0.1)
    raise SensorError("camd socket not ready: %s" % last_error)


def reset(freq=18200000, dual_buff=False, choice=None):
    global _sock, _last_seq, _last_snapshot_ms
    if _sock is not None:
        try:
            _sock.close()
        except Exception:
            pass
        _sock = None
    _last_seq = -1
    _last_snapshot_ms = 0
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
    if enable:
        _connect()
    else:
        close()


def _recv_exact(n):
    data = b""
    while len(data) < n:
        chunk = _sock.recv(n - len(data))
        if not chunk:
            raise SensorError("connection closed")
        data += chunk
    return data


def snapshot():
    global _last_seq, _last_snapshot_ms
    _connect()
    for _ in range(5000):
        try:
            _sock.sendall(b"F")
            hdr = _recv_exact(32)
            if hdr[:4] != b"KCF1":
                raise SensorError("bad frame header")
            if hdr[31] == 1:
                # the daemon has no frame yet; it sent only the header
                time.sleep_ms(2)
                continue
            seq = (
                hdr[4]
                | (hdr[5] << 8)
                | (hdr[6] << 16)
                | (hdr[7] << 24)
            )
            y = _recv_exact(320 * 240)
            uv = _recv_exact(160 * 120 * 2)
            if seq == _last_seq:
                # the daemon returned the same buffer; wait for a new one
                time.sleep_ms(1)
                continue
            _last_seq = seq
            # The fallback daemon produces ~25 fps; Krux only needs 15.
            now = time.ticks_ms()
            elapsed = now - _last_snapshot_ms
            if elapsed < 66:
                time.sleep_ms(66 - elapsed)
            _last_snapshot_ms = time.ticks_ms()
            import image

            return image.Image.from_nv12(
                y + uv, 320, 240, 320, 160, 320, 240
            )
        except OSError as e:
            raise SensorError(str(e))
    raise SensorError("no new frame from camd")


def close():
    global _sock, _last_seq, _last_snapshot_ms
    if _sock is not None:
        try:
            _sock.close()
        except Exception:
            pass
        _sock = None
    _last_seq = -1
    _last_snapshot_ms = 0


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