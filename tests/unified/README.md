# Unified opt-in sighash: verification

Checks that this build's signing produces Bitcoin Knots' unified opt-in
signature hash, and that Knots accepts the result.

`vendor/embit` is pinned to the `privkeyio/embit` branch
`unified-sighash-v0.8.1` (tag `v0.8.1-unified-sighash.1`), which implements
the algorithm for all four script types. It is the fork's own commits rebased
onto the embit this repository already vendored, so everything upstream of
v0.8.0 is kept.

The specification is `doc/unified-sighash.md` in Bitcoin Knots, v29.4.2
(knots20260508).

## test_vectors.py

Runs with the ordinary suite (`pytest tests/`). Checks the vendored embit
against Knots' 166 cross-implementation vectors, vendored in `data/`, covering
bare/P2SH, segwit v0, taproot key path and tapscript.

It imports embit normally, with no `sys.path` manipulation, so it exercises the
dependency the editable install in `pyproject.toml` points at rather than a
working tree that happens to sit beside it. Pointed at an embit without the
feature, 167 of its 168 cases fail, which is what makes a pass meaningful.

## knots_interop.py

Drives a Knots regtest node, signs with embit and requires the node to accept
and mine the transaction. The control spends a separate unspent output with
the legacy segwit digest under the opt-in byte and requires rejection for
signature verification failure, not `missing-inputs`.

## krux_knots_e2e.py

The same, through Krux's own `Key`/`Wallet` and `krux.sighash.sign_with`, the
call `PSBTSigner.add_signatures` makes. Asserts the hash type byte is `0x21`
when the PSBT asks for the opt-in and `0x01` when a host rewrites the request
down to the standard one, that Knots mines the result, and that the byte the
review screen would have named is the byte the mined transaction carries. It
also checks that the types the device refuses are refused with no signature
produced.

## cve_2020_14199.py

Builds the attack the CVE describes and runs it against a Knots node. A signer
is shown one input understated, displays a fee of 0.0001 BTC, and signs; the
real transaction pays 9.9901 BTC.

    BIP143 segwit v0   signature valid in the real transaction: True   attack succeeds
    unified opt-in     signature valid in the real transaction: False  attack blocked

Same transaction, same keys, same signer; only the hash type byte differs.

Note the fee cap is disabled (`testmempoolaccept(..., 0)`) so the result
reflects signature validity rather than relay policy. Left enabled, the attack
is stopped by `max-fee-exceeded`, which is mempool policy a miner can ignore,
not consensus.

## Running the node-driven scripts

They need a Bitcoin Knots build and run from its functional test directory,
which supplies the framework and `config.ini`. Copy them there and point
`KRUX_SRC` at this repository's `src/` if it is not two levels up:

    cp tests/unified/*.py <knots-build>/test/functional/
    KRUX_SRC=$PWD/src python3 <knots-build>/test/functional/krux_knots_e2e.py

They take embit from the environment, so they too test the vendored
dependency.

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
