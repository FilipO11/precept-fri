from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
import os

# GENERATE KEYS
k = ec.generate_private_key(ec.SECP384R1())
serialized_private = k.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.BestAvailableEncryption(b"preceptfri")
)

k = k.public_key()
serialized_public = k.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

with open("keys/LS_private_key.key", "wb") as h: 
    h.write(serialized_private)
with open("keys/LS_public_key.key", "wb") as h: 
    h.write(serialized_public)
    
# GENERATE IDS
with open("ids/Content_ID.id", "wb") as h: 
    h.write(os.urandom(32))
with open("ids/LS_ID.id", "wb") as h: 
    h.write(os.urandom(32))
with open("ids/CH_ID.id", "wb") as h: 
    h.write(os.urandom(32))
with open("ids/D_ID.id", "wb") as h:
    did = os.urandom(32)
    h.write(did)

# GENERATE DEVICE DB
with open("DeviceDB.db", "wb") as db:
    db.write(did)
    for i in range(100):
        db.write(os.urandom(32))