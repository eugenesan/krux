# The MIT License (MIT)

# Copyright (c) 2021-2026 Krux contributors

# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
"""Which signature hash this device will use for a PSBT, and whether it did.

A PSBT input may declare a hash type, and that value comes off the wire from a
host this device does not trust. It decides which algorithm signs and what the
signature commits to, so the device decides for itself which types it will ask
embit for, tells the user which one it is about to use, and then checks that
what came out is that.

The unified opt-in is a 0x20 bit in the hash type byte; see
doc/unified-sighash.md in Bitcoin Knots. It selects one message format for
bare/P2SH, segwit v0, taproot key path and tapscript, and commits to every
spent amount, which is what closes CVE-2020-14199 for those inputs.
"""

from embit.psbt import sighash_types_agree
from embit.transaction import SIGHASH
from .krux_settings import t

# Why a transaction cannot be described by one hash type on the review screen.
# An input this wallet holds would be skipped, leaving the transaction signed in
# part.
REFUSED_PARTIAL = "partial"
# Every input would be signed, but with types no one label covers.
REFUSED_MIXED = "mixed"

# The hash types this device will ask sign_with for. Everything else falls back
# to SIGHASH.DEFAULT, which is what sign_with was called with before any hash
# type was passed at all, and under which it signs the inputs asking for ALL and
# skips the rest.
#
# An allowlist rather than a blocklist, because the value comes off the wire from
# a host this device does not trust, and it decides what the signature commits
# to. SIGHASH.NONE commits to no outputs, so its signature lets anyone redirect
# what the input spends. SIGHASH_SINGLE with no output at the input's index does
# the same, and on a legacy input signs a constant that is reusable against any
# transaction spending that key. ANYONECANPAY leaves the other inputs
# uncommitted. None of these are shown to the user, so a transaction asking for
# one would review as an ordinary send.
#
# This bounds what is asked for, not what can come back. Under DEFAULT, sign_with
# still honours an input's own opt-in bit, so a PSBT declaring 0x21 is signed as
# 0x21 without this device naming it. That commits to every output and every
# input, which is the property being protected here. A bare 0x20 is not signed
# under DEFAULT by either side: it is not on this list, and embit refuses it
# against the type asked for.
SIGNABLE_SIGHASH_TYPES = frozenset(
    {
        None,  # the PSBT does not say
        SIGHASH.DEFAULT,  # taproot, commits to everything
        SIGHASH.ALL,
        SIGHASH.UNIFIED | SIGHASH.ALL,  # the unified opt-in
    }
)


class PSBTRefusedError(Exception):
    """No single hash type honestly describes this PSBT.

    `reason` is REFUSED_PARTIAL or REFUSED_MIXED: two different situations the
    user is told apart, because one means part of the transaction would go
    unsigned and the other that every part would be signed with types the review
    screen could not name.
    """

    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason


class PSBTSignError(Exception):
    """Signing failed on a PSBT the user had already approved.

    Kept apart from PSBTRefusedError, which is decided before the user is asked
    to approve anything. Here the failure is a property of the transaction, so
    walking the user through every seed on the device would hit the same failure
    each time while telling them their seeds are at fault.
    """


def derivation_is_ours(key, public_key, derivation_path_obj):
    """Whether one derivation on an input or output belongs to this wallet's key.

    A coordinator given only an xpub omits the fingerprint, which arrives as four
    zero bytes, so an exact comparison alone would answer False for inputs that
    are this wallet's. The fallback derives the key the PSBT names and compares
    it, which is what PSBTSigner._fill_zero_fingerprint_scope does before
    parsing.
    """
    if derivation_path_obj.fingerprint == key.fingerprint:
        return True

    if derivation_path_obj.fingerprint == b"\x00\x00\x00\x00":
        try:
            derived = key.root.derive(derivation_path_obj.derivation)
            return derived.key.sec() == public_key.sec()
        except Exception:  # pylint: disable=W0703
            return False
    return False


def input_is_ours(key, inp):
    """Whether any derivation on this input belongs to this wallet's key"""
    derivations = list(inp.bip32_derivations.items()) + [
        (pub, derivation)
        for pub, (_leaves, derivation) in inp.taproot_bip32_derivations.items()
    ]
    return any(
        derivation_is_ours(key, pub, derivation) for pub, derivation in derivations
    )


def effective_sighash_type(inp, requested):
    """The hash type this input will actually be signed with.

    Mirrors what sign_with resolves before it builds the digest: an input that
    declares nothing takes the requested type, and DEFAULT means ALL for anything
    that is not taproot, because the byte has to name an output type there. A
    caller naming a type owns the opt-in bit, so the request wins where that bit
    is in play.

    The screen shows this rather than the requested type: they differ for the two
    commonest PSBTs, and a screen that names a type no signature carries is
    worse than one that says nothing.
    """
    declared = inp.sighash_type
    effective = requested if declared is None else declared
    if not inp.is_taproot and effective == SIGHASH.DEFAULT:
        effective = SIGHASH.ALL
    # Kept so this stays a faithful mirror of sign_with rather than a shortcut
    # that happens to agree. It cannot fire today: sighash_type only returns
    # something other than DEFAULT when every input already declares that same
    # value, so the request and the effective type are equal before reaching
    # here. It would start mattering the moment sighash_type is allowed to ask
    # for something an input did not declare.
    if (
        requested is not None
        and requested != SIGHASH.DEFAULT
        and (effective | requested) & SIGHASH.UNIFIED
    ):
        effective = requested
    return effective


def sighash_type(psbt):
    """The hash type to pass to sign_with for this PSBT.

    The inputs' own type where they all ask for the same signable one, and
    SIGHASH.DEFAULT otherwise. Under DEFAULT embit signs the inputs asking for
    ALL and skips the rest, which is what this did before a hash type was passed
    at all.
    """
    declared = {inp.sighash_type for inp in psbt.inputs}
    if len(declared) != 1 or not declared <= SIGNABLE_SIGHASH_TYPES:
        return SIGHASH.DEFAULT
    return declared.pop() or SIGHASH.DEFAULT


def unsignable_inputs(psbt, key):
    """Inputs belonging to this wallet that the signer will skip because the hash
    type they declare is not the one this device is about to ask for.

    Scoped to this wallet's own inputs. An input the device holds no key for
    yields no signature whatever its hash type, and a co-signer finishes it, so
    counting those would refuse the collaborative transactions this device
    exists to take part in.

    An input declaring nothing takes whatever is asked for, and DEFAULT and ALL
    are the same request, so neither is skipped. The comparison is embit's own,
    so this cannot drift from what sign_with actually does.

    Signing past one of these produces a transaction signed less completely than
    the device reports, because the signature count still rises.
    """
    requested = sighash_type(psbt)
    return [
        i
        for i, inp in enumerate(psbt.inputs)
        if inp.sighash_type is not None
        and not sighash_types_agree(inp.sighash_type, requested)
        and input_is_ours(key, inp)
    ]


def screen_sighash_type(psbt, key):
    """The hash type to name on the review screen, and why not where there is none.

    Returns (hash_type, None) when there is one honest thing to show, and
    (None, reason) otherwise. The two reasons are different situations and the
    user is told different things: one means part of the transaction would go
    unsigned, the other that every part would be signed but with types no single
    label describes.

    One place, so the view and the tests cannot describe different behaviour.

    Inputs this wallet holds decide it where there are any. Where there are none
    the whole transaction does, because sign_with also matches the root key
    inside a script with no derivation present, and those inputs still get
    signed.
    """
    requested = sighash_type(psbt)

    if unsignable_inputs(psbt, key):
        return None, REFUSED_PARTIAL

    ours = [inp for inp in psbt.inputs if input_is_ours(key, inp)]
    effective = {
        effective_sighash_type(inp, requested) for inp in (ours or psbt.inputs)
    }
    if len(effective) != 1:
        return None, REFUSED_MIXED

    # The declared type comes off the wire as four little endian bytes with no
    # bound, so where no input matches this wallet the fallback above can carry a
    # value the device would never sign. Naming it on the review screen would
    # describe a signature that cannot exist.
    shown = effective.pop()
    if shown not in SIGNABLE_SIGHASH_TYPES:
        return None, REFUSED_MIXED
    return shown, None


def sighash_label(hash_type):
    """The line shown on the review screen naming the message about to be signed.

    Shown in both states rather than only when the opt-in is used: a host that
    rewrites a request for the unified message down to the standard one gets a
    standard signature, and if only the opt-in were labelled, its absence would
    be indistinguishable from this screen never having said anything.

    The other state is "standard" rather than "legacy" because it is not one
    message: 0x00 on a taproot input is BIP341's, 0x01 off taproot is BIP143's,
    and calling either of them legacy would name the wrong algorithm on the one
    screen whose purpose is naming it.

    Kept to one line on the narrowest display Krux runs on. The summary is at the
    screen height there, so a line that wraps costs the one below it: the fee, or
    this. The word "sighash" is what goes, since the byte beside it is what a
    coordinator reads back.
    """
    if hash_type & SIGHASH.UNIFIED:
        label = t("Unified")
    else:
        label = t("Standard")
    return "%s 0x%02x" % (label, hash_type)


def signed_hash_types(tx):
    """Every signature on this PSBT: where it sits, the hash type it carries, and
    the signature itself.

    Read back off the signatures rather than predicted, so it says what was
    actually produced however the signer decided to produce it. The raw bytes are
    returned alongside the hash type because a host can pre-populate any of
    these slots: a caller comparing only which slots are occupied would take a
    signature that replaced planted junk for one that was already there.
    """

    def hash_type(raw):
        # a taproot key path signature is 64 bytes and carries no trailing byte,
        # which is SIGHASH.DEFAULT rather than an absent hash type. A value the
        # host left empty has no hash type at all; it is reported as one nothing
        # matches so it can never be mistaken for the type on the screen.
        if not raw:
            return None
        return raw[-1] if len(raw) != 64 else SIGHASH.DEFAULT

    found = {}
    for i, inp in enumerate(tx.inputs):
        for pubkey, sig in inp.partial_sigs.items():
            raw = bytes(sig)
            found[(i, "partial", bytes(pubkey.sec()))] = (hash_type(raw), raw)
        for pubkey, sig in inp.taproot_sigs.items():
            raw = bytes(sig)
            found[(i, "taproot", str(pubkey))] = (hash_type(raw), raw)
        # Two separate reads, not one chained pair. The pinned embit puts a taproot
        # key path signature in both taproot_key_sig and final_scriptwitness; an
        # embit that added one while still writing the witness would, under an
        # elif, silently stop this from reading the witness, and a signature would
        # escape the check that this whole function exists to feed.
        key_sig = getattr(inp, "taproot_key_sig", None)
        if key_sig is not None:
            raw = bytes(key_sig)
            found[(i, "taproot_key", b"")] = (hash_type(raw), raw)
        if inp.final_scriptwitness and inp.final_scriptwitness.items:
            raw = bytes(inp.final_scriptwitness.items[0])
            found[(i, "witness", b"")] = (hash_type(raw), raw)
    return found


def sign_with(psbt, key):
    """Sign psbt with the hash type it asks for, and hold the result to it.

    Raises PSBTRefusedError when there is no single hash type to describe the
    transaction, and PSBTSignError when signing itself fails or produces
    something other than what the review screen promised. Nothing is signed in
    either case: the fields signing writes are put back the way the coordinator
    sent them before the error is raised.
    """
    shown_sighash, refused_because = screen_sighash_type(psbt, key)
    if shown_sighash is None:
        raise PSBTRefusedError(refused_because)

    # Name the hash type the PSBT asks for rather than relying on the signer's
    # default. The unified opt-in selects a signature hash algorithm, so which one
    # gets used is worth stating here rather than inheriting from whichever embit
    # happens to be installed.
    requested = sighash_type(psbt)

    # The PSBT comes off a QR from a host this device does not trust, and signing
    # mutates the inputs in place as it goes, so a malformed one that raises
    # partway through would otherwise leave a half-signed object behind for
    # whatever runs next. Only the signature fields are snapshotted: those are the
    # only ones sign_with writes, and the only ones a later step could mistake for
    # a complete signature.
    #
    # Deliberately not a serialize/parse round trip of the whole PSBT, which would
    # buy the same thing. A PSBT read in compressed mode holds its spent output
    # privately and carries no previous transaction, so re-reading it falls back to
    # the witness_utxo -- a field a hostile coordinator is free to lie in, and one
    # the review screens deliberately do not read. A round trip would therefore
    # sign a different amount from the one that was displayed, which is the whole
    # of CVE-2020-14199.
    restore = [
        (
            inp,
            inp.partial_sigs.copy(),
            inp.taproot_key_sig,
            inp.final_scriptwitness,
            inp.sighash_type,
        )
        for inp in psbt.inputs
    ]
    before = signed_hash_types(psbt)

    try:
        sigs_added = psbt.sign_with(key.root, sighash=requested)

        # The screen made a claim; this is where it is held to it. sign_with also
        # signs inputs it matches by finding the root key inside a script, with no
        # derivation to predict from, so what was produced is read back off the
        # signatures rather than worked out in advance. Nothing is handed back
        # unless every signature this call added carries the byte the user was
        # shown.
        # Compared by signature, not by which slots are occupied. A host can plant
        # a signature in any slot this device is about to fill, and matching on the
        # slot alone would then read the real one as something that was already
        # there and never check it.
        added = {
            where: hash_type
            for where, (hash_type, raw) in signed_hash_types(psbt).items()
            if before.get(where, (None, None))[1] != raw
        }
        if sigs_added == 0 or not added:
            raise PSBTSignError("cannot sign")
        if set(added.values()) - {shown_sighash}:
            raise PSBTSignError(
                "signed hash types %s do not match the 0x%02x shown to the user"
                % (sorted(set(added.values())), shown_sighash)
            )
    except PSBTSignError:
        _restore_signatures(restore)
        raise
    except Exception as e:  # pylint: disable=W0703
        # Any failure here is a property of the PSBT, which is untrusted input,
        # rather than of the seed.
        _restore_signatures(restore)
        raise PSBTSignError(str(e))


def _restore_signatures(restore):
    """Puts the signature fields back the way the coordinator sent them"""
    for inp, partial_sigs, taproot_key_sig, witness, sighash_type_ in restore:
        inp.partial_sigs = partial_sigs
        inp.taproot_key_sig = taproot_key_sig
        inp.final_scriptwitness = witness
        inp.sighash_type = sighash_type_
