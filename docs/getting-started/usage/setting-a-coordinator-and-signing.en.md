Once you've generated a mnemonic, securely backed it up, and successfully tested the recovery process, you’re ready to set up a coordinator.

Krux works with:

- [Sparrow Wallet](https://www.sparrowwallet.com/) (desktop)
- [Specter Desktop](https://specter.solutions/) (desktop)
- [Liana](https://wizardsardine.com/liana/) (desktop)
- [Bitcoin Safe](https://bitcoin-safe.org/) (desktop)
- [Nunchuk](https://nunchuk.io/) (mobile)
- [BlueWallet](https://bluewallet.io/) (mobile)
- [Bitcoin Keeper](https://bitcoinkeeper.app/) (mobile)
- [BULL Wallet](https://wallet.bullbitcoin.com) (mobile)

## Step 1: Install the Coordinator Wallet

Download and install the appropriate version of your chosen coordinator wallet for your device and operating system.

## Step 2: Create a New Wallet with Krux as a Signer

Depending on the coordinator, the steps to add Krux as a signer may vary slightly:

- **Specter and Nunchuk Single-sig:** Add Krux key, then create a wallet that uses it.
- **Specter and Nunchuk Multisig:** Add Krux key, add other keys, then create a wallet that uses them.
- **Sparrow, Liana, Bitcoin Safe and BlueWallet**: Create a wallet (or vault in Blue Wallet) and add key(s) during setup.
- **Bitcoin Keeper**: Add Wallet -> Create Wallet, select single-key or multi-key, and add key(s). Or add key(s), then Add Wallet -> Create Wallet and select that key(s).
<!-- -->

1. Load a mnemonic and wallet in Krux.

    <img src="../../../img/maixpy_amigo/load-mnemonic-seq-mnemonic-300.png" class="amigo">
    <img src="../../../img/maixpy_amigo/load-mnemonic-seq-overview-300.png" class="amigo">
    <img src="../../../img/maixpy_m5stickv/load-mnemonic-seq-mnemonic-250.png" class="m5stickv">
    <img src="../../../img/maixpy_m5stickv/load-mnemonic-seq-overview-250.png" class="m5stickv">

2. On your coordinator, select **"Krux"** if it's listed among the available signer devices. If not, choose **"Other"** or a QR code-compatible signer such as **"SeedSigner"**. Since Krux supports various QR formats, other available options may also be compatible.
3. When prompted by your coordinator to import signer's public key, access the `Extended Public Key` on Krux.

    <img src="../../../img/maixpy_amigo/extended-public-key-selected-300.png" class="amigo">
    <img src="../../../img/maixpy_m5stickv/extended-public-key-selected-250.png" class="m5stickv">

4. Export an *XPUB* (or *YPUB, ZPUB*, .., based on the script type) as a QR code.

    <img src="../../../img/maixpy_amigo/extended-public-key-xpub-qr-menu-selected-300.png" class="amigo">
    <img src="../../../img/maixpy_amigo/extended-public-key-wsh-xpub-qr-300.png" class="amigo">
    <img src="../../../img/maixpy_m5stickv/extended-public-key-xpub-qr-menu-selected-250.png" class="m5stickv">
    <img src="../../../img/maixpy_m5stickv/extended-public-key-wsh-xpub-qr-250.png" class="m5stickv">

5. Scan this QR code with your coordinator.
6. Ensure the coordinator’s wallet attributes (policy type, script type, fingerprint, and derivation) match those in Krux.

Alternatively, you can export the extended public keys as files to an SD card. Instead of displaying them as QR codes, select the `XPUB - Text` option, then choose `Save to SD card`.

<img src="../../../img/maixpy_amigo/extended-public-key-menu-300.png" class="amigo">
<img src="../../../img/maixpy_amigo/extended-public-key-wsh-xpub-text-300.png" class="amigo">
<img src="../../../img/maixpy_m5stickv/extended-public-key-menu-250.png" class="m5stickv">
<img src="../../../img/maixpy_m5stickv/extended-public-key-wsh-xpub-text-250.png" class="m5stickv">

## Step 3: Load and Backup Wallet Descriptor (Multisig Only)

1. In your coordinator, export the wallet descriptor containing information about the wallet and all cosigners:
    - **Sparrow**: "Descriptor"
    - **Specter**: "Export Wallet"
    - **Liana**: "Wallet Descriptor"
    - **Bitcoin Safe**: "Register multisig on signers" on step 6 or "Wallet Descriptor"
    - **Nunchuk**: "Export Wallet Configuration"
    - **BlueWallet**: "Export Coordination Setup"
    - **Bitcoin Keeper**: "Wallet configuration file"
2. Export the descriptor as a QR code or file.
3. On Krux, go to **Wallet -> Wallet Descriptor** to scan the descriptor QR code or load it via SD card.

<img src="../../../img/maixpy_amigo/wallet-load-prompt-300.png" class="amigo big">
<img src="../../../img/maixpy_amigo/wallet-wsh-load-prompt-300.png" class="amigo big">
<img src="../../../img/maixpy_m5stickv/wallet-load-prompt-250.png" class="m5stickv big">
<img src="../../../img/maixpy_m5stickv/wallet-wsh-load-prompt-250.png" class="m5stickv big">

4. If you access **Wallet -> Wallet Descriptor** again, you will be able to:
    - Check the wallet cosigners.
    - Save the descriptor on an SD card (useful if you initially loaded it from QR codes).
    
    **Tip**: Having a backup of the wallet descriptor is essential for recovering your wallet.

## Step 4: Verify Addresses

<img src="../../../img/maixpy_m5stickv/list-address-receive-250.png" align="right" class="m5stickv">
<img src="../../../img/maixpy_amigo/list-address-receive-300.png" align="right" class="amigo">

For single-sig or multisig (after loading a descriptor):

- Go to `Address` on Krux.
- List `Receive Addresses` and `Change Addresses` or use `Scan Address` to verify if addresses from your coordinator are matched by Krux.

<div style="clear: both"></div>

## Step 5: Funding your Wallet

Once addresses are verified, send a small test amount to your wallet. Test signing and sending a transaction before adding more funds.

## Step 6: Sign PSBTs and Messages

### PSBTs

1. Create a transaction in your coordinator.

2. Export the transaction as a QR code.

3. On Krux, go to **Sign -> PSBT -> Load from camera**.

4. Scan the animated QR code.

5. Verify the transaction details. The last line of the summary names the
   signature message that is about to be produced, and the signature Krux
   hands back carries exactly that: `Unified 0x21` if the
   coordinator asked for Bitcoin Knots' unified opt-in signature hash,
   `Standard 0x01` otherwise.

6. If correct, press `Sign to QR code`.

7. Scan the signed transaction QR code back into the coordinator to broadcast it.

Alternatively, you can use an SD card:

Save the transaction as a file on an SD card. On Krux, go to **Sign -> PSBT -> Load from SD card** and `Sign to SD card`. Load the signed transaction on the coordinator and broadcast it.

#### Signature messages Krux will sign

A PSBT input may declare a hash type, and Krux decides for itself which ones
it will ask for. It signs, and names on screen, only these:

| Hash type | Meaning |
| --- | --- |
| *(nothing)* | The default for the script type |
| `0x00` SIGHASH_DEFAULT | Taproot; commits to every input and output |
| `0x01` SIGHASH_ALL | Commits to every input and output |
| `0x21` SIGHASH_ALL&#124;SIGHASH_UNIFIED | The unified opt-in, one message format for every script type |

Anything else is refused rather than signed, because Krux would have no way to
tell you what it was committing to. `SIGHASH_NONE` signs no outputs at all, so
its signature lets anyone redirect what the input spends; `SIGHASH_SINGLE` with
no output at the input's index signs a constant that is reusable against any
transaction spending that key; and `SIGHASH_ANYONECANPAY` leaves the other
inputs uncommitted. None of these are shown to a signer, so a transaction
asking for one would otherwise review as an ordinary send.

When a PSBT's inputs do not reduce to a single type Krux will describe, it
refuses to sign and says which of the two situations applies: part of the
transaction would go unsigned, or every part would be signed but with types no
one label covers. Nothing is signed and nothing is sent in either case.

The unified opt-in is specified in `doc/unified-sighash.md` in Bitcoin Knots.
It commits to the amount and scriptPubKey of every input, which is what closes
CVE-2020-14199 for those inputs, and its message is distinct from every
existing one, so an opted-in transaction cannot be replayed onto a chain that
does not implement it. A signature carrying it is only valid on a chain that
does, so the coordinator must be running Bitcoin Knots.

### Messages

<img src="../../../img/maixpy_m5stickv/sign-message-at-address-prompt-250.png" align="right" class="m5stickv">
<img src="../../../img/maixpy_amigo/sign-message-at-address-prompt-300.png" align="right" class="amigo">

Some coordinators, like Sparrow, allow you to sign messages linked to your wallet's addresses. Signing and verifying a message signature attests to the ownership of an address and serves as an additional test for your setup.

<div style="clear: both"></div>