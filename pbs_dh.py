from Crypto.Math.Primality import generate_probable_safe_prime
from hashlib import sha256
from secrets import randbelow
from fastecdsa.keys import gen_keypair
from json import JSONEncoder

##### Global Parameters ########
# Generated with the command openssl prime -safe -generate -bits 2048
p = 28919751740118116894081508706875480423910153641598203996954918254178624121924256684555633834746594890009913019785615923129682263935316657692158151321384469676570129589971343503480296658356308387573275774414176350785301204635808146111211576912772878945729823294675061500249850206226097244851386082748777729726724138517586783258531203425556618683986239987266900076201261219494039867138976237878129389544552843514179051071743528209941397523565216925825999857172480444646784865225414774603816371551143554483005644357325180879041300880498794704800138848250695898501787892529728481470670229703202981219311764372100102416527
q = (p-1)//2
g = 2

###### Storage classes #########
# These are just to group variables together to clean up passing between functions
# Correspond to messages from the partial blind signature protocol

class SignatureParams:
    def __init__(self, a, b):
        self.a = a
        self.b = b

class BlindedSignature:
    def __init__(self, r, c, s, d):
        self.r = r
        self.c = c
        self.s = s
        self.d = d

class UnblindedSignature:
    def __init__(self, rho, omega, delta, sigma, msg, info):
        self.rho = rho
        self.omega = omega
        self.delta = delta
        self.sigma = sigma
        self.msg = msg
        self.info = info

class SignerState:
    def __init__(self, u, d, s):
        self.u = u
        self.s = s
        self.d = d

class UserState:
    def __init__(self, t1, t2, t3, t4):
        self.t1 = t1
        self.t2 = t2
        self.t3 = t3
        self.t4 = t4


# The flow of the blind signature process should go:
# 1. Signer -> generate_params
# 2. User -> generate_signature_request
# 3. Signer -> sign
# 4. User -> unblind

# Signer class
# Represents the signer (Apple server) who posesses the private key

class Signer:
    #privkey - an integer less than q (the order of the EC), in practice comes from from fastecdsa.keys
    def __init__(self, privkey, hashfunc = sha256):
        self.privkey = privkey
        self.hashfunc = hashfunc

    #info - a string of public info that goes along with the blinded signature, the server has to know this to start the signature process
    def generate_params(self, info):
        u, d, s, a, b = raw_signer_gen_params(self.hashfunc, self.privkey, info)
        return SignerState(u, d, s), SignatureParams(a, b)

    #e - the signature request coming from the user, comes from the generate_signature_request function
    def sign(self, state, e):
        return BlindedSignature(*raw_signer_sign(self.hashfunc, self.privkey, state.u, state.s, state.d, e))

# User class
# Represents the party receiving the signature
class User:
    # pubkey - A point on the EC representing the public key, comes from fastecdsa.keys
    def __init__(self, pubkey, hashfunc = sha256):
        self.hashfunc = hashfunc
        self.pubkey = pubkey

    #Similar to above, the next two functions use shared state and need to be called in sequence

    #sigparams - SignatureParams object, comes from generate_params function above
    #msg - string or bytes object representing the message being signed
    #info - string representing the plaintext auxiliary information to go along with the blinded signature
    def generate_signature_request(self, sigparams, msg, info):
        t1, t2, t3, t4, e = raw_user_blind(self.hashfunc, self.pubkey, msg, info, sigparams.a, sigparams.b)
        return UserState(t1, t2, t3, t4), e
    
    #bsig - BlindedSignature object, comes from sign function above
    #msg - string or bytes object representing the message being signed
    #info - string representing the plaintext auxiliary information to go along with the blinded signature
    def unblind(self, state, bsig, msg, info):
        return UnblindedSignature(*raw_user_unblind(self.hashfunc, self.pubkey, state.t1, state.t2, state.t3, state.t4, bsig.r, bsig.c, bsig.s, bsig.d, msg, info))


#This function can be called by anyone to verify a signature
#The UnblindedSignature object includes the msg and info fields so they do not need to be passed in again
#sig - UnblindedSignature object
#pubkey - public key, point on the EC
def verify_signature(sig, pubkey, hashfunc=sha256):
    return raw_verify_sig(hashfunc, pubkey, sig.info, sig.msg, sig.rho, sig.omega, sig.sigma, sig.delta)


### Encoder/Decode functions ###
########################################################################
# Used for json encoding and decoding the data classes above, so they can be sent across a network

class ECEncoder(JSONEncoder):
    def default(self, obj):
        if( isinstance(obj, bytes) ):
            return obj.hex()
        d = obj.__dict__.copy()
        d[obj.__class__.__name__] = True
        return d

########################################################################


#######################################################################################################
# These functions implement the math for blind signatures, shouldn't be necessary to use these directly
#######################################################################################################
def hashToInt(msg, hashfunc):
    if( isinstance(msg, str) ):
        msg = msg.encode()
    assert isinstance(msg, bytes), "Can only hash bytes or string objects"
    
    h = hashfunc(msg).hexdigest()
    m = int(h, base=16)
    m = m % q
    return m

def hashToPoint(msg, hashfunc):
    m = hashToInt(msg, hashfunc)
    return (m*m)%p

def raw_signer_gen_params(hashfunc, privkey, info):
    u = randbelow(q)
    d = randbelow(q)
    s = randbelow(q)

    z = hashToPoint(info, hashfunc)
    a = pow(g, u, p)
    b = (pow(g,s,p) * pow(z,d,p)) % p

    return (u, d, s, a, b)

def raw_user_blind(hashfunc, pubkey, msg, info, a, b):
    if isinstance(msg, str):
        msg = msg.encode()

    assert isinstance(msg, bytes), "Can only sign bytes or string objects"

    t1 = randbelow(q)
    t2 = randbelow(q)
    t3 = randbelow(q)
    t4 = randbelow(q)

    z = hashToPoint(info, hashfunc)
    
    alpha = (pow(g,t1,p) * pow(pubkey,t2,p)) % p
    alpha = (alpha * a) % p

    beta = (pow(g,t3,p) * pow(z,t4,p)) % p
    beta = (beta * b) % p

    epsilon = hashToInt(str(alpha) + str(beta) + str(z) + msg.hex(), hashfunc)
    e = (epsilon - t2 - t4) % q

    return (t1, t2, t3, t4, e)

def raw_signer_sign(hashfunc, privkey, u, s, d, e):
    c = (e - d) % q
    r = (u - c * privkey) % q

    return (r, c, s, d)

def raw_user_unblind(hashfunc, pubkey, t1, t2, t3, t4, r, c, s, d, msg, info):
    if isinstance(msg, str):
        msg = msg.encode()

    assert isinstance(msg, bytes), "Can only sign bytes or string objects"

    rho = (r + t1) % q
    omega = (c + t2) % q
    sigma = (s + t3) % q
    delta = (d + t4) % q

    z = hashToPoint(info, hashfunc)
    alpha = (pow(g,rho,p) * pow(pubkey,omega,p)) % p
    beta = (pow(g,sigma,p) * pow(z,delta,p)) % p


    assert (omega + delta) % q == hashToInt(str(alpha) + str(beta) + str(z) + msg.hex(), hashfunc), "Incorrect values from signer"
        
    return (rho, omega, delta, sigma, msg, info)

def raw_verify_sig(hashfunc, pubkey, info, msg, rho, omega, sigma, delta):
    if isinstance(msg, str):
        msg = msg.encode()

    assert isinstance(msg, bytes), "Can only sign bytes or string objects"

    left = (omega + delta) % q

    z = hashToPoint(info, hashfunc)
    alpha = (pow(g,rho,p) * pow(pubkey,omega,p)) % p
    beta = (pow(g,sigma,p) * pow(z,delta,p)) % p

    right = hashToInt(str(alpha) + str(beta) + str(z) + msg.hex(), hashfunc)

    return left == right