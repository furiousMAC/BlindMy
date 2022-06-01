from pbs import *
from pbs import Signer
from pbs import User
from fastecdsa.keys import gen_keypair, import_key
from fastecdsa.curve import P224
from hashlib import sha256
import json
import socket
import comm
import sys
from typing import List, Tuple
from tqdm import tqdm
import debug
import multiprocessing as mp
import pdb
from itertools import repeat

HOST = "localhost"
PORT = 4444

_, PUB = import_key("key.pub", P224, True)


manager = mp.Manager()
_states = manager.dict()
_reqs = manager.dict()

_pubkeys = dict()
_u = dict()
_params = dict()
_hints = dict()

def gen_keys(privateseed: str, numkeys: int) -> List[str]:
    print(f"Generating {numkeys} keys")
    pubkeys = []
    for i in tqdm(range(numkeys)):
        pkey = hashToInt(privateseed + str(i), P224, sha256)
        pubkey = pkey * P224.G
        pubkeyx = '{:056x}'.format(pubkey.x)
        pubkeys.append(pubkeyx)
    return pubkeys

unblindSigs = manager.dict()

def parallelUnblind(i, pubkeys, u, states, hints, msg):
    global unblindSigs
    bsig = msg["blinded_sig" + str(i)]
    keyhash = sha256(pubkeys[i].encode()).hexdigest()
    sig = u.unblind(states[i], bsig, keyhash, str(i),
                        hint=hints[i], aux=pubkeys[i])
    unblindSigs[i] = sig

def unblindKeys(u: User, states: List[UserState], msg: dict, pubkeys: List[str], hints: List[int]) -> List[UnblindedSignature]:
    global unblindSigs
    #sigs = []
    num_keys = msg["num_keys"]

    print(f"Attempting to unblind {num_keys} keys with {len(states)} states")

    inputs = range(int(num_keys))
    pool = mp.Pool()
    pool.starmap(parallelUnblind, zip(inputs, repeat(pubkeys), repeat(u), repeat(states), repeat(hints), repeat(msg)))

    
#    for i in tqdm(range(int(num_keys))):
#        bsig = msg["blinded_sig" + str(i)]
#        keyhash = sha256(pubkeys[i].encode()).hexdigest()
#        sig = u.unblind(states[i], bsig, keyhash, str(i),
#                        hint=hints[i], aux=pubkeys[i])
#        sigs.append(sig)
#    pdb.set_trace()
    retVals = list()
    for i in range(int(num_keys)):
        retVals.append(unblindSigs[i])
    return retVals


def get_params(msg: dict) -> Tuple[List[SignatureParams], List[int]]:
    params = []
    num_reqs = msg["num_keys"]
    hints = []

    print(f"Attempting to decode {num_reqs} params from server")
    for i in range(int(num_reqs)):
        params.append(msg["params" + str(i)])
        hints.append(msg["hint" + str(i)])
    return params, hints

def parallelReq(i):
    global _states
    global _reqs
    keyhash = sha256(_pubkeys[i].encode()).hexdigest()
    state, req = _u.generate_signature_request(
        _params[i], keyhash, str(i), hint=_hints[i])
    _states[i] = state
    _reqs[i] = req


def gen_requests(u: User, params: List[SignatureParams], pubkeys: List[str], hints: List[int]) -> Tuple[List[UserState], List[int]]:
    print(
        f"Generating {len(pubkeys)} signing requests from {len(params)} server params")
    global _states
    global _reqs

    global _pubkeys
    global _u
    global _params
    global _hints

    _pubkeys = pubkeys
    _u = u
    _params = params
    _hints = hints

    inputs = range(len(pubkeys))
    pool = mp.Pool()
    res = pool.map(parallelReq, inputs)

 #   states = list()
 #   reqs = list()
 #   for i in tqdm(range(len(pubkeys))):
 #       keyhash = sha256(pubkeys[i].encode()).hexdigest()
 #       state, req = u.generate_signature_request(
 #           params[i], keyhash, str(i), hint=hints[i])
 #       states.append(state)
 #       reqs.append(req)
 #   pdb.set_trace()

    states_retval = list()
    reqs_retval = list()
    for i in range(len(pubkeys)):
        states_retval.append(_states[i])
        reqs_retval.append(_reqs[i])
        
    return (states_retval, reqs_retval)
#    return (_states.values(), _reqs.values())


def handle_server(conn: socket.socket, serial_number: str, numkeys: int, privateseed: str) -> None:
    # generate connection request with serial number as datafield and send request
    print("Sending hello")
    req = {"msg_type": comm.HELLO,
           "serial_number": serial_number, "num_keys": numkeys}
    comm.sendMessage(conn, req)
    print("Waiting for server response")
    u = User(PUB)
    states = []
    pubkeys = []
    hints = []

    while True:
        msg = comm.recvMessage(conn)
        #print("Received message:")
        # print(msg)
        msgType = msg['msg_type']

        if msgType == comm.PARAMS:
            params, hints = get_params(msg)

            pubkeys = gen_keys(privateseed, numkeys)

            (states, reqs) = gen_requests(u, params, pubkeys, hints)

            data = {}
            data['msg_type'] = comm.SIGNREQ
            data['num_keys'] = len(pubkeys)
            for i in range(len(pubkeys)):
                data['req' + str(i)] = reqs[i]

            print(f"Sending requests")

            comm.sendMessage(conn, data)

        elif msgType == comm.BLINDED:
            sigs = unblindKeys(u, states, msg, pubkeys, hints)
            print("Writing keys to file")
            with open("signed_keys.txt", "w") as out:
                for s in sigs:
                    out.write(json.dumps(s, cls=ECEncoder))
                    out.write("\n")
            print("Done")
            sys.exit(0)

        elif msgType == comm.ERROR:
            print(msg['error'])
            return


def main():

    if len(sys.argv) < 3:
        print("Usage: python3 client.py <serial> <privateseed> <number of keys (optional)>")
        print("Serial can be obtained from serialgen.py")
        print("Private seed is a string used as input to a PRG to generate private keys corresponding to the public keys that are signed in this protocol")
        print("Number of keys specifies how many keys will be generated and signed in this execution")
        sys.exit(0)

    serial = sys.argv[1]

    privateseed = sys.argv[2]

    if len(sys.argv) == 4:
        numkeys = int(sys.argv[3])
    else:
        numkeys = 365

    # type: socket.socket
    conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    conn.connect((HOST, PORT))

    handle_server(conn, serial, numkeys, privateseed)


if __name__ == "__main__":
    main()
