# Coldcard PSBT Recovery

A simple program to create a PSBT from various keypaths related to
a [Coldcard](https://coldcardwallet.com). Searches for your
UTXO using <https://Blockstream.info> API calls.

Typical use will use the `public.txt` file exported from a Coldcard. 
For now, it only handles addresses explicitly listed in that file (first five)
but could be improved easily to search more broadly to deposits to a Coldcard.

## Usage

```
# python3 -m pip install --editable .
# rehash
# pbst_recovery data/example.psbt
```

## Requirements

- `python3`
- `pycoin`
- `click`

(See `requirements.txt`)

# From Public.txt File

## Input Data

On your Coldcard, go to Advanced > Micro SD > Dump Summary.

Take the "public.txt" file it makes and feed it to this program.

Lines of this form:

    m/0'/0'/2' => mtCWD93LGCbKydRh4CVoZkk5yryaprtCFN

Are searched on the Blockchain... Any UTXO found will be added to the PSBT.


## Public.txt Usage

```
% psbt_recovery public example-public.txt mtHSVByP9EYZmB26jASDdPVm19gvpecb5R

... (lots of good output) ...
```

# From Miniscript Descriptor


Can take a miniscript descriptor (from Bitcoin Core) and it's address
and find all UTXO for that and build PSBT to move it elsewhere.

Provide also an XPUB and/or XFP to verify those values as it goes
along. They aren't required.

```
% psbt_recovery desc "sh(wpkh([e0000002/84'/0'/0'/0/9]022c...43434))#v90hljj9"

... (lots of good output) ...
```

# Help Messages


```
% psbt_recovery --help
Usage: psbt_recovery [OPTIONS] COMMAND [ARGS]...

Options:
  -p, --payout_address 1bitcoinaddr
  -o, --output_psbt FILENAME
  -t, --testnet                   Assume testnet3 addresses
  --help                          Show this message and exit.

Commands:
  desc
  public
```

---

```
% psbt_recovery desc --help
Usage: psbt_recovery desc [OPTIONS] FULL-DESCRIPTOR Address

Options:
  --xfp, --fingerprint TEXT  Provide XFP value, otherwise some checks will be
                             skipped

  --xpub TEXT                Optional XPUB at hardened depth
  --depth INTEGER            Depth of xpub given
  --help                     Show this message and exit.
```

---

```
% psbt_recovery public --help
Usage: psbt_recovery public [OPTIONS] PUBLIC_TXT

Options:
  --xfp, --fingerprint TEXT  Provide XFP value, otherwise discovered from file
  --gap INTEGER              Widen search by searching /[0/1]/0...gap
  --xpub TEXT                Limit work to single xpub
  --dump_addrs TEXT          Dump addrs and paths we will check (and stop)
  --help                     Show this message and exit.
```
