from fastecdsa.point import Point
from fastecdsa.curve import P224
from fastecdsa.curve import Curve
from hashlib import sha256
from secrets import randbelow
from fastecdsa.keys import gen_keypair
from json import loads
from json import JSONEncoder
from fastecdsa.util import mod_sqrt
from typing import Tuple, Union, Callable, Any
import mmap
import array
import ctypes
import pdb

# Implements partial blind signatures from here: https://www.iacr.org/archive/crypto2000/18800272/18800272.pdf

###### Storage classes #########
# These are just to group variables together to clean up passing between functions
# Correspond to messages from the partial blind signature protocol

class SignatureParams:
    def __init__(self, a, b):
        self.a = a # type: Point
        self.b = b # type: Point

class BlindedSignature:
    def __init__(self, r, c, s, d):
        self.r = r # type: int
        self.c = c # type: int
        self.s = s # type: int
        self.d = d # type: int

class UnblindedSignature:
    def __init__(self, rho, omega, delta, sigma, msg, info, aux = ""):
        self.rho = rho # type: int
        self.omega = omega # type: int
        self.delta = delta # type: int
        self.sigma = sigma # type: int 
        self.msg = msg # type: str
        self.info = info # type: str
        self.aux = aux # type: str

class SignerState:
    def __init__(self, u, d, s):
        self.u = u # type: int
        self.s = s # type: int
        self.d = d # type: int

class UserState:
    def __init__(self, t1, t2, t3, t4):
        self.t1 = t1 # type: int
        self.t2 = t2 # type: int 
        self.t3 = t3 # type: int
        self.t4 = t4 # type: int


# The flow of the blind signature process should go:
# 1. Signer -> generate_params
# 2. User -> generate_signature_request
# 3. Signer -> sign
# 4. User -> unblind

# Signer class
# Represents the signer (Apple server) who posesses the private key

class Signer:
    #privkey - an integer less than q (the order of the EC), in practice comes from from fastecdsa.keys
    def __init__(self, privkey : int, curve : Curve = P224, hashfunc = sha256):
        self.privkey = privkey # type: int
        self.curve = curve # type: Curve
        self.hashfunc = hashfunc 

    #info - a string of public info that goes along with the blinded signature, the server has to know this to start the signature process
    def generate_params(self, info : str, pointhash : Point = None, hint : int = None):
        u, d, s, a, b = raw_signer_gen_params(self.curve, self.hashfunc, self.privkey, info, pointhash, hint) # type int
        return SignerState(u, d, s), SignatureParams(a, b)

    #e - the signature request coming from the user, comes from the generate_signature_request function
    def sign(self, state : SignerState, e : int):
        return BlindedSignature(*raw_signer_sign(self.curve, self.hashfunc, self.privkey, state.u, state.s, state.d, e))

# User class
# Represents the party receiving the signature
class User:
    # pubkey - A point on the EC representing the public key, comes from fastecdsa.keys
    def __init__(self, pubkey : Point, curve : Curve = P224, hashfunc = sha256):
        self.curve = curve
        self.hashfunc = hashfunc
        self.pubkey = pubkey

    #Similar to above, the next two functions use shared state and need to be called in sequence

    #sigparams - SignatureParams object, comes from generate_params function above
    #msg - string or bytes object representing the message being signed
    #info - string representing the plaintext auxiliary information to go along with the blinded signature
    def generate_signature_request(self, sigparams : SignatureParams, msg : str, info : str, pointhash : Point = None, hint : int = None):
        t1, t2, t3, t4, e = raw_user_blind(self.curve, self.hashfunc, self.pubkey, msg, info, sigparams.a, sigparams.b, pointhash, hint)
        return UserState(t1, t2, t3, t4), e
    
    #bsig - BlindedSignature object, comes from sign function above
    #msg - string or bytes object representing the message being signed
    #info - string representing the plaintext auxiliary information to go along with the blinded signature
    def unblind(self, state : UserState, bsig : BlindedSignature, msg : str, info : str, pointhash : Point = None, hint : int = None, aux : str = ""):
        return UnblindedSignature(*raw_user_unblind(self.curve, self.hashfunc, self.pubkey, state.t1, state.t2, state.t3, state.t4, bsig.r, bsig.c, bsig.s, bsig.d, msg, info, pointhash, hint, aux))


#This function can be called by anyone to verify a signature
#The UnblindedSignature object includes the msg and info fields so they do not need to be passed in again
#sig - UnblindedSignature object
#pubkey - public key, point on the EC
def verify_signature(sig : UnblindedSignature, pubkey : Point, curve : Curve = P224, hashfunc = sha256, pointhash : Point = None, hint : int = None):
    return raw_verify_sig(curve, hashfunc, pubkey, sig.info, sig.msg, sig.rho, sig.omega, sig.sigma, sig.delta, pointhash, hint)


### Encoder/Decode functions ###
########################################################################
# Used for json encoding and decoding the data classes above, so they can be sent across a network

class ECEncoder(JSONEncoder):
    def default(self, obj):
        if( isinstance(obj, bytes) ):
            return obj.hex()
        d = obj.__dict__.copy()
        for k in d:
            if isinstance(d[k], Point):
                (x,y) = (d[k].x, d[k].y)
                d[k] = (x,y, d[k].curve.oid)
        d[obj.__class__.__name__] = True
        return d

def tupleToPoint(t):
    return Point(t[0], t[1], Curve.get_curve_by_oid(bytes.fromhex(t[2])))

def as_dict(d):
    
    if "SignatureParams" in d:
        return as_sig_params(d)
    elif "BlindedSignature" in d:
        return as_blinded_signature(d)
    elif "UnblindedSignature" in d:
        return as_unblinded_signature(d)
    elif isinstance(d, dict):
        return d
    else:
        return loads(d)


def as_sig_params(d):
    assert d["SignatureParams"] == True, "Attempt to decode a SignatureParams object failed, wrong type"

    a = tupleToPoint(d["a"])
    b = tupleToPoint(d["b"])

    return SignatureParams(a, b)

def as_blinded_signature(d):
    assert d["BlindedSignature"] == True, "Attempt to decode a BlindedSignature object failed, wrong type"

    return BlindedSignature(d["r"], d["c"], s = d["s"], d = d["d"])

def as_unblinded_signature(d):
    assert d["UnblindedSignature"] == True, "Attempt to decode a UnblindedSignature object failed, wrong type"

    return UnblindedSignature(d["rho"], d["omega"], d["delta"], d["sigma"], d["msg"], d["info"], d["aux"])

########################################################################


#######################################################################################################
# These functions implement the math for blind signatures, shouldn't be necessary to use these directly
#######################################################################################################
def hashToInt(msg: Union[bytes, str], curve: Curve, hashfunc: Callable) -> int:
    if( isinstance(msg, str) ):
        msg = msg.encode()
    assert isinstance(msg, bytes), "Can only hash bytes or string objects"

    h = hashfunc(msg).hexdigest()
    m = int(h, base=16)
    m = m % curve.q
    return m

# Uses method from Boneh et al. "Short Signatures from the Weil Pairing"
# Attempt to hash input to an x coordinate, if that value is not on the elliptic curve
# rehash and try again until it is
# From testing, takes on average ~80 attempts per input to find a point on the curve for P224
def hashToPoint(msg: Union[bytes, str], curve: Curve, hashfunc: Callable, hint: int = None, limit: int =10) -> Tuple[Point, int]:
    if( isinstance(msg, str) ):
        msg = msg.encode()
    assert isinstance(msg, bytes), "Can only hash bytes or string objects"
    
    limit = 2 ** limit

    counter = 0

    if not hint is None:
        counter = hint

    while(counter < limit):
        h = hashfunc(msg)
        h.update(("|" + str(counter)).encode())
        h = h.hexdigest()
        m = int(h, base=16)
        x = m % curve.p
        y = curve.evaluate(x)
        try:
            (y1, y2) = mod_sqrt(y, curve.p)
        except:
            counter += 1
            continue

        if curve.is_point_on_curve((x, y1)):
            return Point(x, int(y1), curve), counter

        if curve.is_point_on_curve((x, y2)):
            return Point(x, int(y2), curve), counter

        counter += 1

    raise Exception("Limit exceeded mapping input to curve")

def raw_signer_gen_params(curve: Curve, hashfunc: Callable, privkey: int, info: Union[bytes, str], pointhash: Union[Point, None], hint: Union[int, None]) -> Tuple[int, int, int, Point, Point]:
    u = randbelow(curve.q)
    d = randbelow(curve.q)
    s = randbelow(curve.q)

    if pointhash is None:
        z,_ = hashToPoint(info, curve, hashfunc, hint)
    else:
        z = pointhash

    a = u * curve.G
    z.curve = curve.G.curve
    b = s * curve.G + d * z

    return (u, d, s, a, b)

def raw_user_blind(curve: Curve, hashfunc: Callable, pubkey: Point, msg: Union[bytes, str], info: Union[bytes, str], a: Point, b: Point, pointhash: Union[Point, None], hint: Union[int, None]) -> Tuple[int, int, int, int, int]:
    if isinstance(msg, str):
        msg = msg.encode()

    assert isinstance(msg, bytes), "Can only sign bytes or string objects"

    t1 = randbelow(curve.q)
    t2 = randbelow(curve.q)
    t3 = randbelow(curve.q)
    t4 = randbelow(curve.q)

    if pointhash is None:
        z,_ = hashToPoint(info, curve, hashfunc, hint)
    else:
        z = pointhash
    
    alpha = t1 * curve.G + t2 * pubkey
    alpha = alpha + a

    beta = t3 * curve.G + t4 * z
    beta = beta + b

    epsilon = hashToInt(str(alpha) + str(beta) + str(z) + msg.hex(), curve, hashfunc)
    e = (epsilon - t2 - t4) % curve.q

    return (t1, t2, t3, t4, e)

def raw_signer_sign(curve: Curve, hashfunc: Callable, privkey: int, u: int, s: int, d: int, e: int) -> Tuple[int, int, int, int]:
    #pdb.set_trace()
    c = (e - d) % curve.q
    r = (u - c * privkey) % curve.q

    return (r, c, s, d)

def raw_user_unblind(curve: Curve, hashfunc: Callable, pubkey: Point, t1: int, t2: int, t3: int, t4: int, r: int, c: int, s: int, d: int, msg: Union[bytes, str], info: Union[bytes, str], pointhash: Union[Point, None], hint: Union[int, None], aux: str = "") -> Tuple[int, int, int, int, Union[bytes, str], Union[bytes, str], str]:
    if isinstance(msg, str):
        msg = msg.encode()

    assert isinstance(msg, bytes), "Can only sign bytes or string objects"

    rho = (r + t1) % curve.q
    omega = (c + t2) % curve.q
    sigma = (s + t3) % curve.q
    delta = (d + t4) % curve.q

    if pointhash is None:
        z,_ = hashToPoint(info, curve, hashfunc, hint)
    else:
        z = pointhash

    alpha = rho * curve.G + omega * pubkey
    beta = sigma * curve.G + delta * z

    assert (omega + delta) % curve.q == hashToInt(str(alpha) + str(beta) + str(z) + msg.hex(), curve, hashfunc), "Incorrect values from signer"
        
    return (rho, omega, delta, sigma, msg, info, aux)

def raw_verify_sig(curve: Curve, hashfunc: Callable, pubkey: Point, info: Union[bytes, str], msg: Union[bytes, str], rho: int, omega: int, sigma: int, delta: int, pointhash: Union[Point, None], hint: Union[int, None]) -> bool:
    if isinstance(msg, str):
        msg = msg.encode()

    assert isinstance(msg, bytes), "Can only sign bytes or string objects"

    left = (omega + delta) % curve.q

    if pointhash is None:
        z,_ = hashToPoint(info, curve, hashfunc, hint)
    else:
        z = pointhash

    alpha = rho * curve.G + omega * pubkey
    beta = sigma * curve.G + delta * z

    right = hashToInt(str(alpha) + str(beta) + str(z) + msg.hex(), curve, hashfunc)

    return left == right
