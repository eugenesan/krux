"""
board -- what the hammerhead is, for Krux's firmware.

Krux's firmware asks the board module what it is running on:
``board.config`` is a dictionary, and the keys it reads are

    board.config["type"]                        -- which board
    board.config["lcd"]["width"], ["height"]    -- the display
    board.config["lcd"]["lcd_type"]             -- the panel (unused here)
    board.config["krux"]["display"]["font"]     -- the font's size
    board.config["krux"]["display"]["font_wide"]
    board.config["krux"]["display"]["touch"]    -- is there a touch screen?
    board.config["krux"]["pins"]                -- the pin map

The K210 boards' pin map is a set of MaixPy GPIO numbers.  On the
hammerhead the resources are not GPIOs: the display's backlight is a
sysfs file, the touch screen and the keys are input devices.  So the
values here are the *resources*, and the port's own modules (the
touch screen, the buttons, the light) read them.

The display is 1080x1920 and the font is the 8x16 VGA font (the same
one the kernel's console uses, and the one the port's ``lcd`` module
draws with).
"""

config = {
    "type": "hammerhead",
    "lcd": {
        # THE WIDTH IS THE *LONG* SIDE, ON PURPOSE
        #
        # The firmware computes how many text lines fit on the screen
        # with (krux/display.py):
        #
        #     TOTAL_LINES = board.config["lcd"]["width"] // FONT_HEIGHT
        #
        # so the width it reads is the **vertical** extent of the
        # display.  On the K210 that is right by accident: its panel is
        # 320x240 in the board's own (landscape) terms, and Krux turns
        # it upright, so the portrait height -- 320 -- is the same
        # number as the landscape width the board declares.
        #
        # The hammerhead's panel is 1080x1920 and it is used upright,
        # so the vertical extent is 1920, and that is what the width
        # has to say.  With 1080 there, the firmware thought the screen
        # was 33 lines of 32 pixels -- 1056 pixels -- and so the
        # screen saver animated only the top half of the panel, and
        # every "bottom line" prompt was drawn halfway up the screen.
        #
        # The height is the short side, for the same reason: the touch
        # screen's coordinates are given in the panel's own terms.
        "width": 1920,
        "height": 1080,
        # the panel type: the ST7789 of the K210 boards.  There is no
        # such panel here (the display is already up), so the value
        # only has to be *a* value.
        "lcd_type": 0,
        # the SPI pins of the K210's panel: there is no SPI here.
        "clk": 0,
        "dcx": 0,
        "rst": 0,
        "ss": 0,
    },
    "krux": {
        "display": {
            # the font: the 8x16 VGA font, scaled up twice for the
            # 1080x1920 panel (the display module draws it that way),
            # and twice that for the wide (CJK) glyphs
            #
            # These two numbers and the display module's scale have to
            # agree: the firmware spaces its lines FONT_HEIGHT apart,
            # so a scale that is larger than the declared height makes
            # consecutive lines overlap.
            "font": (24, 48),
            "font_wide": (48, 48),
            # there is a touch screen
            "touch": True,
        },
        "pins": {
            # the display's backlight: the lm3630's brightness file
            "BACKLIGHT": "/sys/class/backlight/lm3630/brightness",
            # the touch screen and the keys, as the input devices
            "TOUCH_IRQ": "/dev/input/event1",
            # the phone's keys: the power key and the volume keys
            "BUTTON_A": "/dev/input/event0",
            "BUTTON_B": "/dev/input/event2",
            "BUTTON_C": "/dev/input/event2",
        },
    },
    "board_info": {},
}
