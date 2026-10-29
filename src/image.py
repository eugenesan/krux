"""image -- wrapper around the native _image module."""

try:
    import _image
    from _image import Image as _NativeImage
    _HAS_NATIVE = True
except ImportError:
    _image = None
    _HAS_NATIVE = False


class Image:
    def __init__(self, size=None, copy_to_fb=False, *a, **k):
        if _HAS_NATIVE:
            if isinstance(size, (tuple, list)) and len(size) >= 2:
                self._native = _NativeImage((size[0], size[1]))
            else:
                self._native = _NativeImage((0, 0))
        else:
            self._w = size[0] if (isinstance(size, (tuple, list)) and size) else 0
            self._h = size[1] if (isinstance(size, (tuple, list)) and len(size) > 1) else 0
            self._buf = bytearray(self._w * self._h * 2)
            self._native = None
        self.size = size
        self.copy_to_fb = copy_to_fb

    def _w(self):
        if self._native:
            return self._native.width()
        return self._w

    def _h(self):
        if self._native:
            return self._native.height()
        return self._h

    def width(self):
        if self._native:
            return self._native.width()
        return self._w

    def height(self):
        if self._native:
            return self._native.height()
        return self._h

    def to_bytes(self, *a, **k):
        if self._native:
            return self._native.to_bytes()
        return bytes(self._buf)

    def clear(self, *a, **k):
        if self._native:
            self._native.clear()
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

    def draw_image(self, *a, **k):
        return self

    def to_grayscale(self, *a, **k):
        return self

    def binary(self, *a, **k):
        return self

    def lens_corr(self, *a, **k):
        return self

    def save(self, *a, **k):
        return self

    def get_statistics(self, *a, **k):
        if self._native:
            return self._native.get_statistics()
        class S:
            l_mean = l_stdev = a_mean = a_stdev = b_mean = b_stdev = 0
            def median(self): return 0
        return S()

    def find_qrcodes(self, *a, **k):
        if _HAS_NATIVE:
            return _image.find_qrcodes(self._native, *a, **k)
        return []

    def get_histogram(self, *a, **k):
        class H:
            def get_threshold(self):
                class T:
                    def value(self): return 128
                return T()
        return H()

    def find_blobs(self, *a, **k):
        return []

    @staticmethod
    def from_nv12(data, src_w, src_h, stride_y, stride_uv, dst_w, dst_h,
                  gray=False, crop=None, hmirror=False, vflip=False):
        if _HAS_NATIVE:
            return _image.from_nv12(data, src_w, src_h, stride_y,
                                    stride_uv, dst_w, dst_h, 1 if gray else 0)
        img = Image(size=(dst_w, dst_h))
        return img