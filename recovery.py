#!/usr/bin/env python3
#
# To use this, install with:
#
#   pip install --editable .
#
# That will create the command "psbt_recover" in your path... or just use "./psbt_recover ..." here
#
#
import click, sys, os, pdb, struct, io, json, re, time
from psbt import BasicPSBT, BasicPSBTInput, BasicPSBTOutput
from pprint import pformat
from binascii import b2a_hex as _b2a_hex
from binascii import a2b_hex
from collections import namedtuple
from base64 import b64encode, b64decode
from pycoin.tx.Tx import Tx
from pycoin.tx.TxOut import TxOut
from pycoin.tx.TxIn import TxIn
from pycoin.encoding import b2a_hashed_base58, hash160
from pycoin.serialize import b2h_rev, b2h, h2b, h2b_rev
from pycoin.contrib.segwit_addr import encode as bech32_encode
from pycoin.key.BIP32Node import BIP32Node
import urllib.request

b2a_hex = lambda a: str(_b2a_hex(a), 'ascii')
#xfp2hex = lambda a: b2a_hex(a[::-1]).upper()

TESTNET = False

def explora(*parts): 
    base = 'https://blockstream.info/'
    if TESTNET:
        base += 'testnet/'

    url = f'{base}api/' + '/'.join(parts)

    time.sleep(0.1)
    with urllib.request.urlopen(url) as response:
       return json.load(response)

def str2ipath(s):
    # convert text to numeric path for BIP174
    for i in s.split('/'):
        if i == 'm': continue
        if not i: continue      # trailing or duplicated slashes

        if i[-1] in "'ph":
            assert len(i) >= 2, i
            here = int(i[:-1]) | 0x80000000
        else:
            here = int(i)
            assert 0 <= here < 0x80000000, here

        yield here

def xfp2str(xfp):
    # Standardized way to show an xpub's fingerprint... it's a 4-byte string
    # and not really an integer. Used to show as '0x%08x' but that's wrong endian.
    return b2a_hex(struct.pack('>I', xfp)).upper()

def str2path(xfp, s):
    # output binary needed for BIP-174
    p = list(str2ipath(s))
    return struct.pack('<%dI' % (1 + len(p)), xfp, *p)

def calc_pubkey(xpubs, path):
    # given a map of paths to xpubs, and a single path, calculate the pubkey
    assert path[0:2] == 'm/'

    hard_prefix = '/'.join(s for s in path.split('/') if s[-1] == "'")
    hard_depth = hard_prefix.count('/')

    want = ('m/'+hard_prefix) if hard_prefix else 'm'
    assert want in xpubs, f"Need: {want} to build pubkey of {path}"

    node = BIP32Node.from_hwif(xpubs[want])
    parts = [s for s in path.split('/') if s != 'm'][hard_depth:]

    # node = node.subkey_for_path(path[2:])
    if not parts:
        assert want == path
    else:
        for sk in parts:
            node = node.subkey_for_path(sk)

    return node.sec()
    

@click.command()
@click.argument('public_txt', type=click.File('rt'))
@click.argument('payout_address', type=str)
@click.argument('out_psbt', type=click.File('wb'))
@click.option('--testnet', '-t', help="Assume testnet3 addresses", is_flag=True, default=False)
@click.option('--xfp', '--fingerprint', help="Provide XFP value, otherwise discovered from file", default=None)
def recovery(public_txt, payout_address, out_psbt, testnet, xfp=None):

    global TESTNET
    TESTNET = testnet

    ''' Match lines like:
            m/0'/0'/0' => n3ieqYKgVR8oB2zsHVX1Pr7Zc31pP3C7ZJ
            m/0/2 => mh7finD8ctq159hbRzAeevSuFBJ1NQjoH2
        and also 
            m => tpubD6NzVbkrYhZ4XzL5Dhayo67Gorv1YMS7j8pRUvVMd5odC2LBPLAygka9p7748JtSq82FNGPppFEz5xxZUdasBRCqJqXvUHq6xpnsMcYJzeh
    '''
    pat_dest = re.compile(r"(m[0-9'/]*)\s+=>\s+(\w+)")

    # match pubkeys, including SLIP132 confusion
    pat_pk = re.compile(r"(\wpub\w{100,140})")

    addrs = []
    xpubs = {}
    for ln in public_txt:

        m = pat_dest.search(ln)
        if m:
            path, addr = m.group(1), m.group(2)

            xp = pat_pk.search(addr)
            if xp:
                xp = xp.group(1)
                if path not in xpubs:
                    xpubs[path] = xp
                elif xpubs[path] != xp:
                    if xp[0] in 'vVuU':
                        # slip-132 junk
                        pass
                    else:
                        print(f'Conflict for {path} xpub:\n  {xp}\n  {xpubs[path]}')
                    
            else:
                #print(f"{path} => {addr}")
                assert path[0:2] == 'm/'
                
                addrs.append( (path, addr) )

                if addr.startswith('tb1') and not TESTNET:
                    print("Looks like TESTNET addresses; switching.")
                    TESTNET = True

        if not xfp:
            if 'master key fingerprint: 0x' in ln:
                # pre 2.1.0 firmware w/ LE32 value
                xfp = int(ln.split(': ')[1], 16)
            elif 'master key fingerprint: ' in ln:
                # after 2.1.0 firmware w/ BE32 value
                xfp, = struct.unpack('>I', a2b_hex(ln.split(': ')[1].strip()))
                
            if xfp:
                print("Fingerprint is: " + xfp2str(xfp))

    if not addrs:
        print("No addresses found!")
        sys.exit(1)

    print("Found %d xpubs: %s" % (len(xpubs), '    '.join(xpubs)))
    print("Found %d addresses. Checking for balances.\n" % len(addrs))

    # verify we have enough data
    trouble = 0
    for path, addr in addrs:
        try:
            calc_pubkey(xpubs, path)
        except AssertionError as exc:
            print(str(exc))
            trouble += 1

    if trouble:
        sys.exit(1)

    spending = []
    amt = 0
    psbt = BasicPSBT()
                

    for path, addr in addrs:
        print(f"addr: {addr} ... ", end='')

        rr = explora('address', addr, 'utxo')

        if not rr:
            print('nada')
            continue

        here = 0
        for u in rr:
            here += u['value']

            tt = TxIn(h2b_rev(u['txid']), u['vout'])
            spending.append(tt)
            #print(rr)
            pin = BasicPSBTInput(idx=len(psbt.inputs))
            psbt.inputs.append(pin)

            calc_pubkey(xpubs, path)

            pin.bip32_paths[pubkey] = str2path(xfp, path)

        print('%.8f BTC' % (here / 1E8))
        amt += here

        if len(spending) > 15:
            print("Reached practical limit on # of inputs. "
                    "You'll need to repeat this process again later.")
            break

    txn = Tx(2,spending,[])



if __name__ == '__main__':
    recovery()

# EOF
