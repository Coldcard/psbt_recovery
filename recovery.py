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
from pprint import pformat, pprint
from binascii import b2a_hex as _b2a_hex
from binascii import a2b_hex
from io import BytesIO
from collections import namedtuple
from base64 import b64encode, b64decode
from pycoin.coins.bitcoin.Tx import Tx, TxOut, TxIn
from pycoin.networks.registry import network_for_netcode

#from pycoin.coins.bitcoin.TxOut import TxOut
#from pycoin.coins.bitcoin.TxIn import TxIn
#from pycoin.ui import standard_tx_out_script   => network.contract.for_address
#from pycoin.encoding import b2a_hashed_base58, hash160
from pycoin.encoding.hexbytes import b2h_rev, b2h, h2b, h2b_rev
from pycoin.contrib.segwit_addr import encode as bech32_encode
from pycoin.key.BIP32Node import BIP32Node
from pycoin.convention import tx_fee
import urllib.request

b2a_hex = lambda a: str(_b2a_hex(a), 'ascii')
#xfp2hex = lambda a: b2a_hex(a[::-1]).upper()

BTC = network_for_netcode("BTC")

TESTNET = False

def explora(*parts, is_json=True):
    base = 'https://blockstream.info/'
    if TESTNET:
        base += 'testnet/'

    url = f'{base}api/' + '/'.join(parts)

    time.sleep(0.1)
    with urllib.request.urlopen(url) as response:
       return json.load(response) if is_json else response.read()

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
    hard_depth = hard_prefix.count('/') + 1

    want = ('m/'+hard_prefix) if hard_prefix else 'm'
    assert want in xpubs, f"Need: {want} to build pubkey of {path}"

    node = BTC.parse.bip32(xpubs[want])
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
@click.option('--gap', help="Widen search by searching /[0/1]/0...gap", default=None, type=int)
@click.option('--xpub', 'single_xpub', help="Limit work to single xpub", default=None)
def recovery(public_txt, payout_address, out_psbt, testnet, xfp=None, gap=None, single_xpub=None):

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

    if gap and not single_xpub:
        print("Must specify xpub if gap feature to be used")
        sys.exit(1)

    addrs = []
    xpubs = {}
    last_xpub = None
    for ln in public_txt:

        m = pat_dest.search(ln)
        if m:
            path, addr = m.group(1), m.group(2)

            xp = pat_pk.search(addr)
            if xp:
                xp = xp.group(1)
                if path not in xpubs:
                    xpubs[path] = xp
                    last_xpub = xp
                elif xpubs[path] != xp:
                    if xp[0] in 'vVuUzyZY':
                        # slip-132 junk
                        pass
                    else:
                        print(f'Conflict for {path} xpub:\n  {xp}\n  {xpubs[path]}')
                    
            else:
                #print(f"{path} => {addr}")
                assert path[0:2] == 'm/'

                if single_xpub and last_xpub != single_xpub:
                    continue
                
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

    pubkeys = {}
    if single_xpub:
        assert single_xpub in xpubs.values(), "Specific xpub not found: " + repr(xpubs)
        the_path = [p for p,xp in xpubs.items() if xp == single_xpub][0]
        the_path += '/{change}/{index}'

        if gap:
            print(f"Will use deriv path: {the_path}")
            wallet = BTC.parse.bip32(single_xpub)
            addr_fmt = None
            for ch in range(2):
                for idx in range(gap):
                    p = the_path.format(change=ch, index=idx)
                    node = wallet.subkey(ch).subkey(idx)

                    garbage = dict((a,b) for a,b,*c in BTC.output_for_public_pair(node.public_pair()))
                    if not addr_fmt:
                        assert idx==0 and ch==0
                        expect = addrs[0][1]
                        for k,v in garbage.items():
                            if v == expect:
                                addr_fmt = k
                                print(f"Address format will be: {addr_fmt}")
                                break
                        else:
                            assert not expect, "Could not find 0/0 addr in public?!"

                    addr = garbage[addr_fmt]
                    print(addr)

                    pubkeys[p] = node.sec()
                    if idx < 5 and ch == 0:
                        assert (p, addr) in addrs, f'Got {addr} for {p} but wanted/expected: {addrs[0][0]} => {addrs[0][1]}'
                    addrs.append( (p, addr) )
    else:
        print("Found %d xpubs: %s" % (len(xpubs), '    '.join(xpubs)))

    print("Found %d addresses. Checking for balances.\n" % len(addrs))

    if 0:
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
    total = 0
    psbt = BasicPSBT()

    for path, addr in addrs:
        print(f"addr: {path}=>{addr} ... ", end='')

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

            pubkey = calc_pubkey(xpubs, path)

            pin.bip32_paths[pubkey] = str2path(xfp, path)

            # fetch the UTXO for witness signging
            td = explora('tx', u['txid'], 'hex', is_json=False)
            outpt = Tx.from_hex(td.decode('ascii')).txs_out[u['vout']]

            with BytesIO() as b:
                outpt.stream(b)
                pin.witness_utxo = b.getvalue()


        print('%.8f BTC' % (here / 1E8))
        total += here

        if len(spending) > 15:
            print("Reached practical limit on # of inputs. "
                    "You'll need to repeat this process again later.")
            break

    assert total, "sorry didnt find any UTXO"

    print("Found total: %.8f BTC" % (total / 1E8))

    print("Planning to send to: %s" % payout_address)

    #dest_scr = standard_tx_out_script(payout_address)
    dest_scr = BTC.contract.for_address(payout_address)

    txn = Tx(2,spending,[TxOut(total, dest_scr)])

    fee = tx_fee.recommended_fee_for_tx(txn)

    # placeholder, single output that isn't change
    pout = BasicPSBTOutput(idx=0)
    psbt.outputs.append(pout)

    print("Guestimate fee: %.8f BTC" % (fee / 1E8))

    txn.txs_out[0].coin_value -= fee

    # write txn into PSBT
    with BytesIO() as b:
        txn.stream(b)
        psbt.txn = b.getvalue()

    out_psbt.write(psbt.as_bytes())

    print("PSBT to be signed:\n\n\t" + out_psbt.name, end='\n\n')
    

if __name__ == '__main__':
    recovery()

# EOF
