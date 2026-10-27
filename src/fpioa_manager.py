"""fpioa_manager stub for the Nexus 5 port.

The K210's pin muxer is irrelevant on a phone: the display and touch are
already wired by the stock kernel.  Provided so that modules that import
`fm` keep importing; `register` is a no-op.
"""


class _FM:
    def register(self, *a, **k):
        return None


fm = _FM()
