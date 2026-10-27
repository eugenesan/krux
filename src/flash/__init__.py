"""
flash -- the K210's SPI flash, as far as this device needs one.

WHY THIS EXISTS
---------------

The firmware's "Erase User's Data" (the wipe) and its "flash tools"
page are written against the K210's 16 MB SPI flash: they read and
erase it in 4 KB blocks, and the SPIFFS area (the user's settings
and mnemonics) starts at 0xD00000.

**This device has no SPI flash.**  Its settings are two ordinary
files in the firmware's data directory:

    flash/settings.json     the settings
    flash/seeds.json        the encrypted mnemonics

and the wipe has to remove *those*, not 3 MB of some other device.

THE GUARD IS THE POINT
----------------------

A module that erases raw flash on this device can **brick it**: the
offsets the firmware uses (0xD00000..0x1000000) mean nothing here,
and a module that mapped them onto the wrong device -- the internal
flash, the eMMC -- would take the partition table or the bootloader
with it, and the phone would not come back.

So this module:

* opens **no** block device and no device node at all: it only ever
  touches files in the settings directory;
* **refuses** any address outside the SPIFFS area, so the firmware's
  own loop (which walks the whole flash) cannot make it write
  anywhere else;
* treats the settings area as a byte range over the two files, so
  the firmware's read/erase/write calls behave the way they were
  written.

WHAT THE ERASE DOES
-------------------

`erase()` removes the user's data -- the settings and the mnemonics
-- which is what the button says.  The address is checked first: an
erase outside the SPIFFS area raises, it does nothing.

The firmware's "update the firmware" page also uses this module
(erasing and writing the flash to put a new firmware on the K210).
That does not apply here: there is no firmware to write, and the
firmware is not in the SPI flash.  The write path therefore raises
rather than pretending to work.

WHERE IT GOES
--------------

The settings live in a **directory** called "flash", and a directory
wins over a module of the same name -- so this module is that
directory's `__init__.py`, and the firmware's `import flash` finds
it there.
"""

import os

# The K210's flash geometry, as the firmware expects it.
FLASH_SIZE = 2**24
SPIFFS_ADDR = 0xD00000
ERASE_BLOCK_SIZE = 0x1000

# Where this device keeps what the SPIFFS area held.
FLASH_DIR = "flash"
SETTINGS_FILE = "settings.json"
MNEMONICS_FILE = "seeds.json"

# The files, in the order the address space is laid out.
FILES = (SETTINGS_FILE, MNEMONICS_FILE)

# The message the guard raises.  It is one string on purpose: the
# implicit concatenation of two string literals and the % operator
# do not mix the way they do in CPython.
_OUT_OF_AREA = "flash: 0x%x..0x%x is not in the SPIFFS area (0x%x..0x%x)"


def _path(name):
    """The path of one of the files, relative to the working directory"""
    # MicroPython's os module has no os.path, so the names are joined
    # by hand.
    return FLASH_DIR + "/" + name


def _sizes():
    """The size of each file (0 if it is not there)"""
    sizes = []
    for name in FILES:
        try:
            sizes.append(os.stat(_path(name))[6])
        except OSError:
            sizes.append(0)
    return sizes


def _check(address, length):
    """Refuse anything that is not inside the SPIFFS area"""
    if address < SPIFFS_ADDR or address + length > FLASH_SIZE:
        raise ValueError(_OUT_OF_AREA % (address, address + length, SPIFFS_ADDR, FLASH_SIZE))


def read(address, length):
    """Reads `length` bytes at `address` out of the settings area"""
    _check(address, length)
    out = bytearray(b"\xff" * length)
    offset = address - SPIFFS_ADDR
    for name, size in zip(FILES, _sizes()):
        if offset >= size:
            offset -= size
            continue
        take = min(size - offset, length)
        if take <= 0:
            break
        try:
            with open(_path(name), "rb") as f:
                f.seek(offset)
                data = f.read(take)
        except OSError:
            break
        out[0 : len(data)] = data
        offset = 0
        length -= len(data)
        if length <= 0:
            break
    return bytes(out)


def write(address, data):
    """Not supported: there is no firmware in a SPI flash on this device"""
    _check(address, len(data))
    raise OSError("flash: this device has no flash to write to")


def erase(address, length):
    """Removes the user's data: the settings and the encrypted mnemonics"""
    _check(address, length)
    for name in FILES:
        try:
            os.remove(_path(name))
        except OSError:
            pass
    return True
