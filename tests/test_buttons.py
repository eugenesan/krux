import pytest


def test_generic_button_default_values(m5stickv):
    from krux.buttons import Button, RELEASED

    button = Button()
    assert button.value() == RELEASED
    assert not button.event()


def test_key_value_and_event_follow_evdev(mocker, m5stickv):
    import evdev
    from krux.buttons import _Key, PRESSED, RELEASED

    key = _Key(10, evdev.KEY_POWER)
    mocker.patch(
        "evdev.read",
        side_effect=[
            (evdev.EV_KEY, evdev.KEY_POWER, 1),
            None,
            None,
            None,
        ],
    )
    assert key.value() == PRESSED
    assert key.event() is True
    assert key.event() is False

    mocker.patch(
        "evdev.read",
        side_effect=[
            (evdev.EV_KEY, evdev.KEY_POWER, 0),
            None,
        ],
    )
    assert key.value() == RELEASED


def test_key_ignores_other_keys_and_event_types(mocker, m5stickv):
    import evdev
    from krux.buttons import _Key, RELEASED

    key = _Key(10, evdev.KEY_POWER)
    mocker.patch(
        "evdev.read",
        side_effect=[
            (evdev.EV_KEY, evdev.KEY_VOLUMEUP, 1),
            (evdev.EV_ABS, evdev.KEY_POWER, 1),
            None,
            None,
        ],
    )
    assert key.value() == RELEASED
    assert key.event() is False


def test_button_wrappers_delegate_to_the_open_key(mocker, m5stickv):
    import evdev
    from krux import buttons

    key = mocker.MagicMock()
    key.value.return_value = buttons.PRESSED
    key.event.return_value = True
    mocker.patch.object(buttons.buttons_control, "enter", key)

    button = buttons.ButtonEnter(10)
    assert button.value() == buttons.PRESSED
    assert button.event() is True
    key.value.assert_called_once()
    key.event.assert_called_once()


def test_m5stickv_keys_are_opened_from_board_pins(m5stickv):
    import board
    from krux.buttons import buttons_control

    pins = board.config["krux"]["pins"]
    assert buttons_control.enter.fd == pins["BUTTON_A"]
    assert buttons_control.page.fd == pins["BUTTON_B"]
    assert buttons_control.page_prev is None


def test_amigo_opens_all_three_keys(amigo):
    import board
    from krux.buttons import buttons_control

    pins = board.config["krux"]["pins"]
    assert buttons_control.enter.fd == pins["BUTTON_A"]
    assert buttons_control.page.fd == pins["BUTTON_B"]
    assert buttons_control.page_prev.fd == pins["BUTTON_C"]


def test_missing_board_key_is_none(m5stickv):
    # m5stickv has no BUTTON_C: the port must not create a phantom key.
    from krux.buttons import buttons_control

    assert buttons_control.page_prev is None


def test_key_poll_flushes_the_display(mocker, m5stickv):
    import evdev
    import lcd
    from krux.buttons import _Key

    key = _Key(10, evdev.KEY_POWER)
    mocker.patch("evdev.read", return_value=None)
    key.value()
    lcd.flush.assert_called()
