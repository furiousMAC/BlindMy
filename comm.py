# {'msg_type' : 'HELLO', serial: "12356"}
import json
import struct
import pbs
from pbs import ECEncoder

#USED FOR MESSAGE TYPE TRACKING
HELLO = 1
PARAMS = 2
SIGNREQ = 3
BLINDED = 4
END = 5
ERROR = -1

def sendError(conn, err):
    msg = {"msg_type": ERROR, "error": err}
    sendMessage(conn, msg)

def sendMessage(conn, data: dict):
    payload = json.dumps(data, cls=ECEncoder).encode()
    packet = struct.pack(">I", len(payload)) + payload
    #print(f"Sending {len(payload)} bytes")
    conn.send(packet)

def recvN(conn, n):
    dat = b''
    c = 0
    while c < n:
        newdat = conn.recv(n-c)
        c += len(newdat)
        dat += newdat
    return dat

def recvMessage(conn):
    toRecv = struct.unpack(">I", recvN(conn, 4))[0]
    print(f"Going to recv {toRecv} bytes")
    payload = recvN(conn, toRecv)
    return json.loads(payload, object_hook=pbs.as_dict)

