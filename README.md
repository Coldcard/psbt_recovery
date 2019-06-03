# PSBT Recovery

A simple program to create a PSBT from various keypaths related to
a Coldcard. Searches for UTXO using <https://Blockstream.info/> API calls.

Typical use will use the "public.txt" file exported from a Coldcard. 
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
- `pycoin` version 0.80
- `click`

(See `requirements.txt`)

## Input Data

On your Coldcard, go to Advanced > Micro SD > Dump Summary.

Take the "public.txt" file it makes and feed it to this program.

Lines of this form:

    m/0'/0'/2' => mtCWD93LGCbKydRh4CVoZkk5yryaprtCFN

Are searched on the Blockchain... Any UTXO found will be added to the PSBT.


# Example Usage

```
% psbt_recory example-public.txt output.psbt mtHSVByP9EYZmB26jASDdPVm19gvpecb5R

... (lots of good output) ...
```
