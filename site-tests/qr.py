"""Encode localement un QR standard avec libqrencode."""

from ctypes import CDLL, POINTER, Structure, c_char_p, c_int, c_ubyte
from ctypes.util import find_library
import struct
import zlib


class QRCode(Structure):
    _fields_ = [("version", c_int), ("width", c_int), ("data", POINTER(c_ubyte))]


class QREncoder:
    def __init__(self):
        name = find_library("qrencode")
        if not name:
            raise RuntimeError("Installez la bibliothèque libqrencode pour activer le site 2FA.")
        self.library = CDLL(name)
        self.library.QRcode_encodeData.argtypes = [c_int, c_char_p, c_int, c_int]
        self.library.QRcode_encodeData.restype = POINTER(QRCode)
        self.library.QRcode_free.argtypes = [POINTER(QRCode)]
        self.library.QRcode_free.restype = None

    def png(self, uri):
        content = uri.encode("ascii")
        # Version automatique et niveau de correction M.
        qr = self.library.QRcode_encodeData(len(content), content, 0, 1)
        if not qr:
            raise RuntimeError("Impossible d’encoder le QR TOTP.")
        try:
            width = qr.contents.width
            modules = qr.contents.data[:width * width]
        finally:
            self.library.QRcode_free(qr)
        scale, border = 5, 4
        margin = b"\xff" * (border * scale)
        size = (width + 2 * border) * scale
        blank = b"\x00" + b"\xff" * size
        rows = [blank] * (border * scale)
        for start in range(0, len(modules), width):
            pixels = b"".join((b"\x00" if bit & 1 else b"\xff") * scale
                              for bit in modules[start:start + width])
            rows.extend([b"\x00" + margin + pixels + margin] * scale)
        rows.extend([blank] * (border * scale))
        header = struct.pack(">IIBBBBB", size, size, 8, 0, 0, 0, 0)
        return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", header)
                + chunk(b"IDAT", zlib.compress(b"".join(rows))) + chunk(b"IEND", b""))


def chunk(name, data):
    return struct.pack(">I", len(data)) + name + data + struct.pack(">I", zlib.crc32(name + data))
