import pytest


@pytest.fixture
def shutdown(mocker, m5stickv):
    """The singleton with the state each test needs, and no real hardware."""
    import time
    from krux.auto_shutdown import auto_shutdown

    auto_shutdown.ctx = None
    auto_shutdown.shutdown_time = 0
    auto_shutdown.time_out = 0
    auto_shutdown.idle = 0
    auto_shutdown.backlight_off = False
    auto_shutdown.last_tick = time.ticks_ms()
    mocker.patch.object(auto_shutdown, "turn_the_backlight_off")
    mocker.patch.object(auto_shutdown, "turn_the_backlight_on")
    return auto_shutdown


def test_seconds_counter_counts_only_elapsed_whole_seconds(mocker, shutdown):
    from krux.auto_shutdown import seconds_counter

    shutdown.shutdown_time = 10
    shutdown.time_out = 10
    shutdown.last_tick = 1000
    mocker.patch("time.ticks_ms", return_value=2500)

    seconds_counter("timer")

    assert shutdown.time_out == 9
    assert shutdown.last_tick == 2500
    shutdown.turn_the_backlight_off.assert_not_called()


def test_idle_deadline_turns_the_backlight_off(mocker, shutdown):
    shutdown.shutdown_time = 10
    shutdown.time_out = 0
    shutdown.last_tick = 0
    mocker.patch("time.ticks_ms", return_value=2000)

    shutdown.seconds_counter()

    assert shutdown.time_out == 0
    shutdown.turn_the_backlight_off.assert_called()


def test_feed_resets_timeout_and_idle_counter(mocker, shutdown):
    shutdown.shutdown_time = 600
    shutdown.time_out = 123
    shutdown.idle = 42
    mocker.patch("time.ticks_ms", return_value=shutdown.last_tick)

    shutdown.feed()

    assert shutdown.time_out == 600
    assert shutdown.idle == 0
    shutdown.turn_the_backlight_on.assert_called_once()


def test_backlight_timeout_is_bounded(shutdown):
    shutdown.shutdown_time = 0
    assert shutdown.backlight_timeout() == 30

    shutdown.shutdown_time = 1000
    assert shutdown.backlight_timeout() == 30

    shutdown.shutdown_time = 20
    assert shutdown.backlight_timeout() == 4
