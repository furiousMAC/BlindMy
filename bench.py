from pbs import *
from pbs import Signer
from pbs import User
from fastecdsa.keys import gen_keypair, import_key
from fastecdsa.curve import P224
from tqdm import tqdm
import time
import json


if __name__ == "__main__":
    msg = "Hello"
    info = "World"
    curve = P224

    priv, _ = import_key("key.pri", P224, False)
    _ , pub = import_key("key.pub", P224, True)

    #priv, pub = gen_keypair(curve)


    #priv = randbelow(q)
    #pub = pow(g,priv,p)

    s = Signer(priv)
    u = User(pub)

    t = time.time()

    for i in tqdm(range(700)):
        #Step 1: signer generates parameters for the signature based on public info, the unencrypted metadata that goes along with this signature
        #signer_state is the returned state of the signer needed to continue this signature later one
        #If multiple signature are happening in parallel these states need to be saved and given back to the sign() function correctly later
        signer_state, params = s.generate_params(info)
        
        #Dump params to JSON and load back again to check that they are equal
        # j = json.dumps(params, cls=ECEncoder)
        # params2 = json.loads(j, object_hook=as_sig_params)
        
        # assert params.a == params2.a and params.b == params2.b, "Error saving and loading from JSON"

        # Network communication #1 from Apple to User would go here

        #Step 2: client generates signature request including the message they want signed.  The message is blinded and returned.  client_state includes random variables needed to unblind the signature later and must be passed into the unblind() function.
        client_state, req = u.generate_signature_request(params, msg, info)

        # Network communication #2 from User to Apple would go here
        
        #Step 3: signer signs the request
        blinded_sig = s.sign(signer_state, req)

        # Network communication #3 from Apple to User would go here

        #Step 4: client unblinds the signature to receive the UnblindedSignature object
        sig = u.unblind(client_state, blinded_sig, msg, info)

        #Verify that the signature is correct
        assert verify_signature(sig, pub), "Signature verification failed"

    print(time.time() - t)