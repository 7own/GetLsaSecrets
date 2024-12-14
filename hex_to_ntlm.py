import hashlib,binascii,sys

if len(sys.argv) != 2 :
    print ("""Usage:
	python3 hex_to_ntlm.py 05fc5d3bd09d7a491aedafdff04957a72b3f41e883142ac7b9e89ecae952873efeb09fd8a5027226127875ffdd763a7759309f87e603b76bf93d68f0a6473678""")
    exit()
hex = sys.argv[1]

decoded_string = bytes.fromhex(hex)

hash = hashlib.new('md4', decoded_string).digest()
print (binascii.hexlify(hash).decode())
