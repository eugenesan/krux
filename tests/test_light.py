def test_light_is_a_noop_on_the_phone():
    """The Nexus port has no controllable white LED.

    Pages still use the Light singleton, so it must exist and accept the
    same calls without touching MaixPy GPIO or the pin muxer.
    """
    from krux.light import Light

    light = Light()
    assert light.circuit is None
    assert light.turn_on() is None
    assert light.turn_off() is None


def test_light_singleton_is_available():
    from krux.light import light

    assert light is not None
    assert light.circuit is None
