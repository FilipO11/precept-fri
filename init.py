from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
import os

# GENERATE KEYS
k = ec.generate_private_key(ec.SECP384R1()).public_key()

serialized_public = k.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

with open("keys/LS_public_key.key", "wb") as h: 
    h.write(serialized_public)
    
# GENERATE IDS
with open("ids/LS_ID.id", "wb") as h: 
    h.write(os.urandom(32))
with open("ids/D_ID.id", "wb") as h: 
    h.write(os.urandom(32))
with open("ids/CH_ID.id", "wb") as h: 
    h.write(os.urandom(32))