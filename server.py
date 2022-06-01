from pbs import *
from pbs import Signer
from pbs import User
from fastecdsa.keys import gen_keypair, import_key
from fastecdsa.curve import P224
import json
import socket
import comm
from serialkey import serialkey
from base64 import b64decode
from Crypto.Hash import HMAC, SHA256
from typing import List, Tuple
from tqdm import tqdm
import sys
import debug
import multiprocessing as mp
import time
from itertools import repeat


HOST = "0.0.0.0"
PORT = 4444

_MSG = "hello"
_INFO = "world"
STATE = None

PRIV, _ = import_key("key.pri", P224, False)

#pointhashes = {}
#hints = {}

#This allows access from multiple processes
manager = mp.Manager()
pointhashes = manager.dict()
hints = manager.dict()

def parallelHash(i):
    pointhashes[i],hints[i] = hashToPoint(str(i), P224, sha256)
    
def setup(numdays: int) -> socket.socket:
    global pointhashes
    global hints
    print("Prehashing metadata to points...")

    inputs = range(numdays)
    pool = mp.Pool()
    res = pool.map(parallelHash, inputs)

#    for i in tqdm(range(numdays)):
#       pointhashes[i], hints[i] = hashToPoint(str(i), P224, sha256)
 
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen(5)
    return server

# def checkSerial(serial: str) -> bool:
#     sbytes = b64decode(serial)
#     s = sbytes[:16]
#     mac = sbytes[16:]

#     h = HMAC.new(serialkey, digestmod=SHA256)
#     h.update(s)
#     testmac = h.digest()

#     if testmac == mac:
#         return True
#     return False

paramStates = manager.dict()
paramParam = manager.dict()

def parallelGenParams(i, pointhashes, s):
    if i in pointhashes:
        (state, param) = s.generate_params(str(i), pointhashes[i])
    else:
        (state, param) = s.generate_params(str(i))

    paramStates[i] = state
    paramParam[i] = param
    
def generate_params(s: Signer, msg: dict) -> Tuple[List[SignerState], List[SignatureParams]]:
    global paramStates
    global paramParam
    
    num_params = msg["num_keys"]
    #params = [] # type: list[SignatureParams]
    #states = [] # type: list[SignerState]

    print(f"Attempting to generate {num_params} parameters")

    inputs = range(num_params)
    pool = mp.Pool()
#def parallelGenParams(i, pointhashes, s):
    pool.starmap(parallelGenParams, zip(inputs, repeat(pointhashes), repeat(s)))

    
    # for i in tqdm(range(num_params)):
    #     if i in pointhashes:
    #         (state, param) = s.generate_params(str(i), pointhashes[i])
    #     else:
    #         (state, param) = s.generate_params(str(i))

    #     states.append(state)
    #     params.append(param)

    states = list()
    params = list()
    for i in range(num_params):
        states.append(paramStates[i])
        params.append(paramParam[i])
    
    return (states, params)

def sign_reqs(s: Signer, states: List[SignerState], msg) -> List[BlindedSignature]:
    num_reqs = msg["num_keys"]
    blinded_sigs = []
    print(f"Attempting to sign {num_reqs} keys")

    for i in tqdm(range(int(num_reqs))):
        req = msg['req' + str(i)]
        blinded_sig = s.sign(states[i], req)
        blinded_sigs.append(blinded_sig)

    return blinded_sigs

def handle_client(client: socket.socket):
    if PRIV == None:
        return

    s = Signer(PRIV)
    states = []
    
    while True:
        msg = comm.recvMessage(client)
        #print("Received message:")
        #print(msg)

        msgType = msg['msg_type']

        if msgType == comm.HELLO:
            
            states, params = generate_params(s, msg)

            data = {}
            data['msg_type'] = comm.PARAMS
            for i in range(len(params)):
                data["params" + str(i)] = params[i]
                if not i in pointhashes:
                    print("Error, asked for value outside of precomputed metadata.  Maybe need to run server.py with a higher command line argument?")
                    data['msg_type'] = comm.ERROR
                    break
                data["hint" + str(i)] = hints[i]

            data['num_keys'] = str(len(params))
            comm.sendMessage(client, data)
            
        elif msgType == comm.SIGNREQ:
            
            blinded_sigs = sign_reqs(s, states, msg)
            
            data = {}
            data['msg_type'] = comm.BLINDED
            for i in  range(len(blinded_sigs)):
                data["blinded_sig" + str(i)] = blinded_sigs[i]
            data['num_keys'] = str(len(blinded_sigs))
            comm.sendMessage(client, data)
            return True

        elif msgType == comm.ERROR:
            print(msg['error'])
            return False

#def handle_hello(client: socket, msg: dict):
#    # Check serial # with db
#    if not checkSerial(msg['serial_number']):
#        comm.sendError(client, "Serial does not exist in db")
#        return False
#    print(f"Serial: {msg['serial_number']} in db")
#    return True

def handle_sig_request(msg: dict):
    keys = msg['keys']
    for i in range(len(keys)):
        keys[i] = chr(ord(keys[i])+1)
    return keys

def main():
    numdays = 365
    if len(sys.argv) == 2:
        numdays = int(sys.argv[1])

    server = setup(numdays)
    print("Server up...")
    while True:
        client, addr = server.accept()
        print(f"Received connection from {addr}")
        if(handle_client(client)):
            print("Sign Successful")
        else:
            print("Sign Unsuccessfull")

if __name__ == "__main__":
	main()

