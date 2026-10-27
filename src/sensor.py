"""
sensor -- the camera, on the hammerhead.

The K210 boards have a camera on the CSI bus and MaixPy's `sensor`
module drives it.  The hammerhead's camera (the IMX179) is behind the
ISP, so the port's own camera path is the V4L2 one in the imaging
server (standalone/cam) -- not a module the firmware can call.

Until that path works, this module is a stand-in: it answers the
firmware's questions about the camera (is there one? what are its
sizes?) and raises a clear error when the firmware asks for a picture.
The camera pages then say so, and the rest of the firmware works.
"""

# the MaixPy sensor constants the firmware uses
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

# the hammerhead's rear camera: 3264x2448
WIDTH = 3264
HEIGHT = 2448


class SensorError(Exception):
    """The camera is not available (yet)."""


class sensor:
    """The camera: the hammerhead's is driven by the imaging server."""

    def __init__(self):
        self.width = WIDTH
        self.height = HEIGHT
        self.pixformat = RGB565
        self.framesize = VGA

    def reset(self, freq=18200000, dual_buff=False, choice=None):
        """The MaixPy reset: nothing to do here."""

    def run(self, enable):
        """The MaixPy run: the imaging server does the streaming."""

    def get_id(self):
        """The camera's chip id: the IMX179."""
        return 0x179

    def set_framesize(self, framesize):
        """The picture size."""
        self.framesize = framesize

    def set_windowing(self, roi):
        """A region of the picture."""

    def set_pixformat(self, pixformat):
        """The picture format."""
        self.pixformat = pixformat

    def set_hmirror(self, hmirror):
        """Mirror the picture."""

    def set_vflip(self, vflip):
        """Flip the picture."""

    def skip_frames(self, num=10, time=0):
        """Throw the first frames away."""

    def snapshot(self):
        """Take a picture: the port's camera path is not there yet."""
        raise SensorError(
            "the camera is not available yet: the imaging server "
            "(standalone/cam) is the port's camera path"
        )

    def close(self):
        """Close the camera."""


def get_id():
    """The camera's chip id: the IMX179."""
    return 0x179


def reset(freq=18200000, dual_buff=False, choice=None):
    """The module level API MaixPy has."""
    return sensor().reset(freq, dual_buff, choice)


def run(enable):
    """The module level API MaixPy has."""
    return sensor().run(enable)


def snapshot():
    """The module level API MaixPy has."""
    return sensor().snapshot()
