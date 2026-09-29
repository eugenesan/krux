# Unified opt-in sighash: verification

Checks that this build's signing produces the unified opt-in signature hash
specified in `doc/unified-sighash.md` in Bitcoin Knots, v29.4.2
(knots20260508).

`vendor/embit` is pinned to the `privkeyio/embit` branch
`unified-sighash-v0.8.1` (tag `v0.8.1-unified-sighash.1`), which implements
the algorithm for all four script types. It is the fork's own commits rebased
onto the embit this repository already vendored, so everything upstream of
v0.8.0 is kept.

## test_vectors.py

Runs with the ordinary suite (`pytest tests/`). Checks the vendored embit
against the 166 cross-implementation vectors from the specification, vendored
in `data/`, covering bare/P2SH, segwit v0, taproot key path and tapscript.

It imports embit normally, with no `sys.path` manipulation, so it exercises the
dependency the editable install in `pyproject.toml` points at rather than a
working tree that happens to sit beside it. Pointed at an embit without the
feature, 167 of its 168 cases fail, which is what makes a pass meaningful.

## ../../test_sighash.py

The device's own rules: which types it will ask for, what it names on the
review screen, what it refuses, and the check that every signature it produced
carries the byte it named. Runs with the normal suite.

## ../../pages/home_pages/test_home_sighash.py

The same claims through the UI: `home.sign_psbt()` is driven end to end for a
PSBT asking for the opt-in, and the review screen is checked to name the
message the emitted signature then carries. Also drives both refusal warnings
and the signing-failure screen, asserting no QR is produced in any of them.
Runs with the normal suite.

## Not in this branch

The node-driven interop scripts -- signing against a live Bitcoin Knots
regtest node, and the CVE-2020-14199 attack run against one -- are not
included here. They need a Knots build and `config.ini` from its functional
test directory, so they are kept out of a tree whose tests all run unattended.
Agreement with a node is instead covered by `test_vectors.py` above, which
checks the digest against the specification's own vectors.
