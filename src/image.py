"""image -- minimal stub for the Nexus 5 port.

MaixPy's `image` module provides a drawing surface (Image) used by a few
pages (QR view, tiny seed, flash tools progress bar).  The phone has no
MaixPy image accelerator, so this is a best-effort pure-Python stand-in:
operations are accepted and discarded.  Pages that depend on pixel-perfect
rendering will look degraded until a real implementation lands, but they
will not crash on import or on the common calls.
"""


class Image:
    def __init__(self, size=None, copy_to_fb=False, *a, **k):
        self.size = size
        self.copy_to_fb = copy_to_fb
        self._w = size[0] if (isinstance(size, (tuple, list)) and size) else 0
        self._h = size[1] if (isinstance(size, (tuple, list)) and len(size) > 1) else 0
        self._buf = bytearray(self._w * self._h * 2)

    def clear(self, *a, **k):
        for i in range(len(self._buf)):
            self._buf[i] = 0
        return self

    def set_pixel(self, *a, **k):
        return self

    def get_pixel(self, *a, **k):
        return 0

    def draw_rectangle(self, *a, **k):
        return self

    def draw_line(self, *a, **k):
        return self

    def draw_string(self, *a, **k):
        return self

    def to_grayscale(self, *a, **k):
        return self

    def binary(self, *a, **k):
        return self

    def to_bytes(self, *a, **k):
        return bytes(self._buf)

    def __repr__(self):
        return "Image(%r)" % (self.size,)
