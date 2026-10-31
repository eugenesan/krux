import pytest


@pytest.fixture
def mock_settings(mocker):
    """Mock Settings to avoid dependency on the real configuration."""
    settings = mocker.MagicMock()
    settings.hardware.touch.threshold = 40
    settings.is_flipped_orientation.return_value = False
    settings_class = mocker.patch("krux.touch.Settings")
    settings_class.return_value = settings
    return settings


@pytest.fixture
def touch(mocker, amigo, mock_settings):
    import evdev
    import board
    from krux.touch import Touch

    fd = object()
    opened = mocker.patch("evdev.open", return_value=fd)
    mocker.patch("evdev.read", return_value=None)
    instance = Touch(width=240, height=135)
    return instance, opened, fd


def events(mocker, values):
    """Make evdev.read hand back exactly these events, then None."""
    mocker.patch("evdev.read", side_effect=list(values) + [None])


def press_events(mocker, x=100, y=100, tracking=1):
    import evdev

    events(
        mocker,
        [
            (evdev.EV_ABS, evdev.ABS_MT_POSITION_X, x),
            (evdev.EV_ABS, evdev.ABS_MT_POSITION_Y, y),
            (evdev.EV_ABS, evdev.ABS_MT_TRACKING_ID, tracking),
        ],
    )


def test_touch_initializes_from_evdev(mocker, amigo, mock_settings):
    import board
    import evdev
    from krux.touch import Touch, IDLE

    fd = object()
    opened = mocker.patch("evdev.open", return_value=fd)
    mocker.patch("evdev.read", return_value=None)

    instance = Touch(width=240, height=135)

    assert instance.width == 240
    assert instance.height == 135
    assert instance.state == IDLE
    assert instance.fd is fd
    assert instance.touch_driver is instance
    opened.assert_called_once_with(board.config["krux"]["pins"]["TOUCH_IRQ"])
    assert instance.threshold(40) is None


def test_clear_regions(touch):
    instance, _, _ = touch
    instance.y_regions = [50, 100, 150]
    instance.x_regions = [60, 120]
    instance.clear_regions()
    assert instance.y_regions == []
    assert instance.x_regions == []


def test_add_y_delimiter(touch):
    instance, _, _ = touch
    instance.add_y_delimiter(50)
    instance.add_y_delimiter(100)
    assert instance.y_regions == [50, 100]


def test_add_y_delimiter_out_of_bounds(touch):
    instance, _, _ = touch
    with pytest.raises(ValueError, match="outside display area"):
        instance.add_y_delimiter(250)


def test_add_x_delimiter(touch):
    instance, _, _ = touch
    instance.add_x_delimiter(45)
    instance.add_x_delimiter(90)
    assert instance.x_regions == [45, 90]


def test_add_x_delimiter_out_of_bounds(touch):
    instance, _, _ = touch
    with pytest.raises(ValueError, match="outside display area"):
        instance.add_x_delimiter(140)


def test_set_regions(touch):
    instance, _, _ = touch
    instance.set_regions(x_list=[30, 60, 90], y_list=[60, 120, 180])
    assert instance.x_regions == [30, 60, 90]
    assert instance.y_regions == [60, 120, 180]


def test_set_regions_invalid_type(touch):
    instance, _, _ = touch
    with pytest.raises(ValueError, match="must be a list"):
        instance.set_regions(x_list="not a list")
    with pytest.raises(ValueError, match="must be a list"):
        instance.set_regions(y_list=123)


@pytest.mark.parametrize(
    "data,x_regions,y_regions,expected_valid",
    [
        ((100, 100), [], [], True),
        ((100, 100), [], [50, 150], True),
        ((100, 100), [40, 120], [], True),
        ((100, 100), [40, 120], [50, 150], True),
        ((30, 100), [40, 120], [], False),
        ((130, 100), [40, 120], [], False),
        ((100, 30), [], [50, 150], False),
        ((100, 160), [], [50, 150], False),
    ],
)
def test_valid_position(touch, data, x_regions, y_regions, expected_valid):
    instance, _, _ = touch
    instance.x_regions = x_regions
    instance.y_regions = y_regions
    assert instance.valid_position(data) == expected_valid


@pytest.mark.parametrize(
    "y_regions,x_regions,touch_point,expected_index",
    [
        ([60, 120], [], (100, 50), 0),
        ([60, 120], [], (100, 80), 0),
        ([60, 120], [], (100, 130), 1),
        ([40, 80, 120], [], (50, 30), 0),
        ([40, 80, 120], [], (50, 50), 0),
        ([40, 80, 120], [], (50, 90), 1),
        ([40, 80, 120], [], (50, 130), 2),
    ],
)
def test_extract_index(touch, y_regions, x_regions, touch_point, expected_index):
    instance, _, _ = touch
    instance.y_regions = y_regions
    instance.x_regions = x_regions
    assert instance._extract_index(touch_point) == expected_index


def test_current_state_idle_to_pressed(touch, mocker):
    import evdev
    from krux.touch import IDLE, PRESSED

    instance, _, _ = touch
    instance.y_regions = [60, 120]
    assert instance.state == IDLE
    press_events(mocker, 100, 100)
    assert instance.current_state() == PRESSED
    assert instance.press_point == []  # current_state only tracks; event() stores


def test_current_state_pressed_to_released(touch, mocker):
    import evdev
    from krux.touch import PRESSED, RELEASED

    instance, _, _ = touch
    instance.state = PRESSED
    instance.x = 100
    instance.y = 100
    instance.press_point = [(100, 100)]
    events(mocker, [(evdev.EV_ABS, evdev.ABS_MT_TRACKING_ID, -1)])
    assert instance.current_state() == RELEASED
    assert instance.release_point == (100, 100)


def test_current_state_released_to_idle(touch, mocker):
    from krux.touch import RELEASED, IDLE

    instance, _, _ = touch
    instance.state = RELEASED
    assert instance.current_state() == IDLE


@pytest.mark.parametrize(
    "press_point,release_point,expected_gesture",
    [
        ((100, 100), (160, 100), 1),
        ((160, 100), (100, 100), 2),
        ((100, 100), (100, 160), 4),
        ((100, 160), (100, 100), 3),
        ((100, 100), (105, 105), None),
    ],
)
def test_gesture_detection(touch, press_point, release_point, expected_gesture):
    from krux.touch import PRESSED

    instance, _, _ = touch
    instance.state = PRESSED
    instance.press_point = [press_point]
    instance.release_point = release_point
    instance.current_state()
    assert instance.gesture == expected_gesture


def test_event_with_validation(touch, mocker):
    instance, _, _ = touch
    instance.y_regions = [50, 150]
    press_events(mocker, 100, 100)
    assert instance.event(validate_position=True) is True
    assert instance.press_point[0] == (100, 100)


def test_event_invalid_position(touch, mocker):
    instance, _, _ = touch
    instance.y_regions = [50, 150]
    press_events(mocker, 100, 30)
    assert instance.event(validate_position=True) is False


def test_event_without_validation(touch, mocker):
    instance, _, _ = touch
    instance.y_regions = [50, 150]
    press_events(mocker, 100, 30)
    assert instance.event(validate_position=False) is True
    assert instance.press_point[0] == (100, 30)


def test_event_only_reports_new_touches(touch, mocker):
    instance, _, _ = touch
    press_events(mocker, 100, 100)
    assert instance.event() is True
    mocker.patch("evdev.read", return_value=None)
    assert instance.event() is False


def test_value(touch, mocker):
    from krux.touch import IDLE

    instance, _, _ = touch
    instance.state = IDLE
    mocker.patch("evdev.read", return_value=None)
    assert instance.value() == 1

    press_events(mocker, 100, 100)
    assert instance.value() == 0

    mocker.patch("evdev.read", return_value=None)
    instance.state = IDLE
    instance.tracking = -1
    assert instance.value() == 1


def test_press_point_averaging(touch):
    from krux.touch import PRESSED

    instance, _, _ = touch
    instance.state = PRESSED
    instance.press_point = [(100, 100), (102, 102), (98, 98)]
    instance._store_points((100, 100))
    assert len(instance.press_point) == 4


@pytest.mark.parametrize(
    "gesture,getter",
    [
        ("SWIPE_RIGHT", "swipe_right_value"),
        ("SWIPE_LEFT", "swipe_left_value"),
        ("SWIPE_UP", "swipe_up_value"),
        ("SWIPE_DOWN", "swipe_down_value"),
    ],
)
def test_swipe_values_and_reset(touch, gesture, getter):
    import krux.touch as touch_module

    instance, _, _ = touch
    instance.gesture = getattr(touch_module, gesture)
    assert getattr(instance, getter)() == 0
    assert instance.gesture is None
    assert getattr(instance, getter)() == 1


def test_current_index(touch):
    instance, _, _ = touch
    instance.index = 5
    assert instance.current_index() == 5


def test_touch_event_integration(touch, mocker):
    instance, _, _ = touch
    instance.y_regions = [0, 40, 80, 120, 160, 200]
    press_events(mocker, 75, 150)
    assert instance.event(validate_position=True) is True
    assert instance.current_index() == 3
