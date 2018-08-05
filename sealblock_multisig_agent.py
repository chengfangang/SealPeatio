# -*- coding: utf-8 -*-
import zerorpc
from ctypes import *
import sys, json
import time
import os
from ecdsa import SigningKey, SECP256k1
import hashlib
import glob
import time, threading
from rlp import decode, encode

from jsonrpclib.SimpleJSONRPCServer import SimpleJSONRPCServer

networtype = 4

mwf = 'C:\\sealblock\\mywalletfile.txt'
dll = CDLL('C:\\sealblock\\credcrypto_app.dll')
addr_ether = 'f33ee4888bc5d2857737622277c272e85ff0e16a'

import bitcoin
import sha3
def _decode_sig(sig):
    return ord(sig[64]), bitcoin.decode(sig[0:32], 256), bitcoin.decode(sig[32:64], 256)

def recoverPub(msg,signature):
    hashedmessage = sha3.keccak_256(msg.encode('utf-8')).hexdigest()
    x, y = bitcoin.ecdsa_raw_recover(hashedmessage.decode('hex'), _decode_sig(signature.decode('hex')))
    pub = str(hex(x))[2:-1].zfill(64) + str(hex(y))[2:-1].zfill(64)
    print pub
    return  pub

hashedTX={}
tsx  = {}
pcys = {}
class CredCryptoRPC(object):
    def sign_message(self, msg):
        e_input = create_string_buffer(msg)
        e_output = create_string_buffer('a' * 1024)
        ret = dll.exportedf_sign_message(addr_ether, byref(e_input),byref(e_output),len(e_output.value))
        if ret == 0:
            return e_output.value
        else:
            raise Exception("Error {0}!".format(ret))

    def sign_transaction(self, tx):
        print 'receiving tx for signing: {0}'.format(tx)
        e_input = create_string_buffer(tx)
        e_output = create_string_buffer('a' * 1024 )
        ret = dll.exportedf_sign_transaction(addr_ether, byref(e_input),len(e_input.value),byref(e_output),len(e_output.value), '')
        if ret == 0:
            return e_output.value
        else:
            raise Exception("Error {0}!".format(ret))

    def get_signer_count(self, fromAddr): 
        print 'get_signer_count: {0}'.format(fromAddr)
        if fromAddr.startswith('0x'): fromAddr = fromAddr[2:].lower()
        e_output = c_int(0)
        signer_output = create_string_buffer('a' * 10240 )
        fromAddr = create_string_buffer(fromAddr)
        ret = dll.exportedf_get_signer_count(byref(fromAddr), byref(e_output), byref(signer_output))
        if ret == 0:
            ss = signer_output.value.replace(',',' ').strip().split(' ')
            print 'get_signer_count', e_output.value, ss
            if e_output.value == 0:
                return json.dumps([])
            return json.dumps(ss)#str(e_output.value)
        else:
            raise Exception("Error {0}!".format(ret))

    #tx fromAddr|toAddr|amount|tx
    def init_tx(self, args):
        print 'init_tx: {0}'.format(args)
        txtype,fromAddr,toAddr,amount,tx,txParams = args.split('|')
        if fromAddr.startswith('0x'): fromAddr = fromAddr[2:].lower()
        if toAddr.startswith('0x'): toAddr = toAddr[2:].lower()
        txid = int(time.time())
        tsx[txid] = {'txtype':txtype,'fromAddr':fromAddr,'toAddr':toAddr,'amount':amount,'tx':tx, 'txid':txid, 'signer':{}}
        tsx[txid]['signercount'] = len(json.loads(self.get_signer_count(fromAddr)))
        tsx[txid]['txParams'] = json.loads(txParams)
        return str(txid)

    def get_tx_info(self, txid):
        print 'get_tx_info: {0}'.format(txid)
        return json.dumps(tsx[int(txid)])

    def sign_transaction_by_id(self, txid):
        print 'sign_transaction_by_id: {0}'.format(txid)
        tx = tsx[int(txid)]
        print 'receiving tx for signing: {0}'.format(tx)
        e_input = create_string_buffer(tx['tx'])
        e_output = create_string_buffer('a' * 1024 )
        fromAddr = create_string_buffer(tx['fromAddr'])
        msig = ''
        if len(tx['signer'].keys()) > 0:
           msig = ':'.join([tx['txtype'], tx['fromAddr'], tx['toAddr'], str(tx['amount']), str(tx['txid'])]) + ';' + ','.join(tx['signer'].values())
        msig = create_string_buffer(msig)
        print 'msig:', msig
        ret = dll.exportedf_sign_transaction(byref(fromAddr), byref(e_input),len(e_input.value),byref(e_output), len(e_output.value), byref(msig))
        if ret == 0:
            return e_output.value
        else:
            raise Exception("Error {0}!".format(ret))

    def signer_signed(self, arg):
        print 'signer_signed: {0}'.format(arg)
        txid, sid, data = arg.split('|')
        if data.startswith('0x'): data = data[2:]
        tx = tsx[int(txid)]

        msg = ':'.join([tx['txtype'], tx['fromAddr'], tx['toAddr'], str(tx['amount']), str(tx['txid'])])
        print 'msg:', msg
        msg = '\x19Ethereum Signed Message:\n' + str(len(msg)) + msg

        pub = recoverPub(msg,data)
        tx['signer'][sid] = pub + data
        print 'signed data:', tx['signer'][sid]
        return '0'

    def create_wallet(self, ads):
        print 'create_wallet: {0}'.format('arg')
        s_ss, s_rs, s_maxmount = ads.split('|')
        ss = ','.join([i.strip() for i in s_ss.lower().replace('0x','').strip().split(',')])
        rs = ','.join([i.strip() for i in s_rs.lower().replace('0x','').strip().split(',')])
        maxmount = s_maxmount.lower().strip()
        sk = SigningKey.generate(curve=SECP256k1).to_string().encode('hex')
        private_key = create_string_buffer(sk)

        ps = '6:EQU:%s;4:MAX:%s;' % (networtype,maxmount)
        if len(ss.strip()) > 0:
            ps += '0:SIG:H:%s;' % ss
        if len(rs.strip()) > 0:
            ps += '3:LST:H:%s;' % rs

        #security_policy = create_string_buffer('3:LST:H:%s;0:SIG:H:%s;4:MAX:%s;6:EQU:4;' % (rs ,ss, maxmount))
        security_policy = create_string_buffer(ps)


        out_address = create_string_buffer('0'*129)
        ret = dll.exportedf_seal_and_save(1, byref(private_key),'',byref(security_policy), byref(out_address));
        if ret != 0:
            raise Exception("Error {0}!".format(ret))

        out_address = out_address[:40]
        with open(mwf,'a+') as f:
            f.write(out_address+"\n")
        return out_address

    def get_wallet_addr(self, aaa):
        print 'get_wallet_addr: {0}'.format('arg')
        #if not os.path.exists(mwf):
        #    return '0'
        #return open(mwf).read()
        return aaa

    def get_pendding_txs(self, aaa):
        pds = []
        for txhash in hashedTX:
            txid = hashedTX[txhash]['txid']
            tx = tsx[int(txid)]
            fromAddr = tx['fromAddr']
            for signer in hashedTX[txhash]['signer']:
                if signer not in tx['signer']:
                    pds.append({'fromAddr':fromAddr, 'txid':txid, 'signer':signer, 'tx':tx})

        return json.dumps(pds)


    def init_new_policy(self, args):
        print 'init_new_policy: {0}'.format(args)
        pname, signerstr, receiverstr, maxmountstr, treceiverstr, tmaxmountstr = args.split('|')
        signer = ','.join([i.strip() for i in signerstr.lower().replace('0x','').strip().split(',')])
        receiver = ','.join([i.strip() for i in receiverstr.lower().replace('0x','').strip().split(',')])
        maxmount = maxmountstr.lower().strip()
        treceiver = ','.join([i.strip() for i in treceiverstr.lower().replace('0x','').strip().split(',')])
        tmaxmount = tmaxmountstr.lower().strip()

        ps = '6:EQU:%s;4:MAX:%s;' % (networtype,maxmount)
        if len(signer.strip()) > 0:
            ps += '0:SIG:H:%s;' % signer
        if len(receiver.strip()) > 0:
            ps += '3:LST:H:%s;' % receiver
        if len(treceiver.strip()) > 0:
            ps += '10000:LST:H:%s;' % treceiver
        if len(tmaxmount.strip()) > 0:
            ps += '10001:MAX:%s;' % tmaxmount

        pid = str(int(time.time()))
        pcys[pid] = {'policy': '%s|%s' % (pname, ps), 'pid': pid}
        pcys[pid]['pname'] = pname
        pcys[pid]['signerstr'] = signerstr
        pcys[pid]['receiverstr'] = receiverstr
        pcys[pid]['maxmountstr'] = maxmountstr
        pcys[pid]['treceiverstr'] = treceiverstr
        pcys[pid]['tmaxmountstr'] = tmaxmountstr

        addrs = create_string_buffer('0'*1024)
        ret =  dll.exportedf_get_policy_managers(byref(addrs), len(addrs.value))
        if ret != 0:
            raise Exception("Error {0}!".format(ret))
        addrs = addrs.value.split('\0')[0]
        addrs = list(set([addrs[i:i+40] for i in xrange(0, len(addrs), 40)]))

        pcys[pid]['managers'] = {}
        for i in addrs:
            pcys[pid]['managers'][i] = '';
        
        return json.dumps(pcys[pid])

    def get_policy_info(self, pid):
        print 'get_policy_info: {0}'.format(pid)
        return json.dumps(pcys[pid])

    def submit_policy(self, pid):

        for i in pcys[pid]['managers'].values():
            if i == '':
                raise Exception("Not approved!")

        if 'subed' in pcys[pid]:
             raise Exception("Already submitted!")

        signed = pcys[pid]['managers'].values()
        while len(signed) < 3:
            signed.append(signed[-1])

        param = pcys[pid]['policy'] + '|' + ','.join(signed)

        print param
        param = create_string_buffer(param)
        ret =  dll.exportedf_add_policy_template(byref(param))
        print 'return value:', ret
        if ret != 0:
            raise Exception("Error {0}!".format(ret))
        pcys[pid]['subed'] = True
        return '0'

    def signer_signed_policy(self, arg):
        print 'signer_signed_policy: {0}'.format(arg)
        pid, sid, data = arg.split('|')
        if data.startswith('0x'): data = data[2:]
        pcy = pcys[pid]

        msg = pcy['policy']
        msg = '\x19Ethereum Signed Message:\n' + str(len(msg)) + msg

        pub = recoverPub(msg,data)
        pcy['managers'][sid] = pub + data
        return '0'



def init_tx_from_rawTX(txhash, wallet_addr, rawtx):
    tx = decode(rawtx.decode('hex'))
    to_addr = tx[3].encode('hex')
    amount = int(tx[4].encode('hex'),16)
    txtype = '0'*40

    ps = '%s|%s|%s|%s|%s|{}' % (txtype, wallet_addr, to_addr, amount, rawtx)
    txid = zrpc.init_tx(ps)
    hashedTX[txhash]={}
    hashedTX[txhash]['txid'] = txid
    hashedTX[txhash]['signer'] = json.loads(zrpc.get_signer_count(wallet_addr))

    print 'new TX:', txid
    print 'signers:', hashedTX[txhash]['signer']


WALLET_PATH = 'C:\\sealblock\\wallets\\'
WALLET_ENC_PATH = 'C:\\sealblock\\enc\\'
MARKER = "CREDCRYPTOMARKER"

if not os.path.exists(WALLET_ENC_PATH): os.mkdir(WALLET_ENC_PATH)

def create_wallet(args):
    '''
    [networktype, password, policyname]
    '''
    print args
    networktype = int(args[0])
    password = args[1]
    policyname = create_string_buffer(args[2])

    out_address = create_string_buffer('0'*129)
    
    ret = dll.exportedf_generate_keypair(networktype, byref(policyname), byref(out_address), len(out_address.value))

    if ret == 0:
        fn = WALLET_ENC_PATH + hashlib.sha512(MARKER + out_address.value.lower().split('\0')[0] + password).hexdigest()
        open(fn, 'a').close()

    return "%s|%s" % (ret, out_address.value)

def import_wallet(args):
    '''
    [networktype, private_key, policy]
    '''
    print args
    private_key = create_string_buffer(args[1])
    policy = create_string_buffer(args[2])
    out_address = create_string_buffer('0'*129)
    ret = dll.exportedf_seal_and_save(int(args[0]), byref(private_key),'0',byref(policy), byref(out_address))

    return "%s|%s" % (ret, out_address.value)


def sign_transaction(args):
    '''
    [wallet_addr, passphrase, rawtx, msig]
    '''
    print args
    wallet_addr = create_string_buffer(args[0])
    passphrase = args[1]
    rawtx = create_string_buffer(args[2])
    msig = create_string_buffer(args[3])

    fn = WALLET_ENC_PATH + hashlib.sha512(MARKER + wallet_addr.value.lower().strip() + passphrase).hexdigest()
    if not os.path.exists(fn):
        return "8000|0"

    txhash = None
    signer_count = len(json.loads(zrpc.get_signer_count(wallet_addr.value)))
    if signer_count > 0:
        txhash = hashlib.sha1(wallet_addr.value + rawtx.value).hexdigest()
        if txhash in hashedTX and len(tsx[int(hashedTX[txhash]['txid'])]['signer'].values()) == signer_count:
            tx = tsx[int(hashedTX[txhash]['txid'])]
            if 'sgxret' not in tx:
                msig = ':'.join([tx['txtype'], tx['fromAddr'], tx['toAddr'], str(tx['amount']), str(tx['txid'])]) + ';' + ','.join(tx['signer'].values())
                msig = create_string_buffer(msig)
            else:
                return "%s|%s" % (tx['sgxret']['ret'], tx['sgxret']['value'])
        else:
            if txhash not in hashedTX:
                init_tx_from_rawTX(txhash, wallet_addr.value, rawtx.value)

            return "8001|0"


    e_output = create_string_buffer('a' * 1024 )
    ret = dll.exportedf_sign_transaction(byref(wallet_addr), byref(rawtx),len(rawtx.value),byref(e_output),len(e_output.value),byref(msig))
    if txhash!= None:
        tsx[int(hashedTX[txhash]['txid'])]['sgxret'] = {'ret':ret, 'value':e_output.value}

    return "%s|%s" % (ret, e_output.value)

def list_wallet_addresses(args):
    '''
    []
    '''
    print args

    fs = glob.glob(WALLET_PATH + "\\*")
    fs = [i.split('\\')[-1] for i in fs]

    wlts = []
    for i in fs:
        if len(i) == 40:
            wlts.append(i)

    return "%s|%s" % (0, ','.join(wlts))



def startJsonRPC():
    server = SimpleJSONRPCServer(('localhost', 6663))
    server.register_function(lambda x: x, 'echo')
    server.register_function(create_wallet, 'create_wallet')
    server.register_function(import_wallet, 'import_wallet')
    server.register_function(sign_transaction, 'sign_transaction')
    server.register_function(list_wallet_addresses, 'list_wallet_addresses')
    print 'SimpleJSONRPCServer started!'
    server.serve_forever()


zrpc = CredCryptoRPC()
def startZeroRPC():
    print 'starting sealblock agent'
    s = zerorpc.Server(zrpc)
    s.bind("tcp://*:6665")
    s.run()

#if __name__ == "__main__" : main()


t = threading.Thread(target=startJsonRPC, name='startJsonRPC')
t.setDaemon(True)
t.start()
t = threading.Thread(target=startZeroRPC, name='startZeroRPC')
t.setDaemon(True)
t.start()

while True:
    time.sleep(1)
