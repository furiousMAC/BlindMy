import sys,json

if len(sys.argv) != 3:
    print("USAGE: python3 extract_keys.py <signed keys file> <output file>")
    print("Extracts public keys from the JSON file containing signed keys and writes them contiguously to the binary output file")
    print("Extracted keys can be given to a puck for broadcasting")
    exit(0)

with open(sys.argv[1]) as keyfile, open(sys.argv[2], "wb") as outfile:
    for line in keyfile:
        #Some annoying stuff here to get all the bytes out of the key msg
        #The key is originally hex, but the generic encoder in pbs.py encodes any byte data as hex so
        #here it is actually doubly hexed
        d = json.loads(line)
        #Decode the hex string to get original bytes, in this case also hex
        #b = bytes.fromhex(d["aux"]).decode().strip()
        # #Pad with zeroes if necessary so that the fromhex() call works
        # b = "0" * (56 - len(b)) + b
        # #Decode the second level of hex, finally into bytes
        # x = bytes.fromhex(b)
        
        b = bytes.fromhex(d["aux"])
        
        outfile.write(b)
