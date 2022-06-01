from serialkey import serialkey
from Crypto.Hash import HMAC, SHA256
import os
from base64 import b64encode

serial = os.urandom(16)
h = HMAC.new(serialkey, digestmod=SHA256)
h.update(serial)

print(b64encode(serial + h.digest()).decode())

