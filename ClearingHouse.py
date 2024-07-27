# IMPORTS
import datetime, os, time, base64
from cryptography import x509
from cryptography.fernet import Fernet
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding

def xor_bytes(s1, s2):
    res = []
    for i in range(min(len(s1),len(s2))):
        res.append(s1[i] ^ s2[i])

    return bytes(res)

# LOAD FROM FILES
with open("pki/sk_ch.pem", "rb") as h:
    pem_data = h.read()
sk_ch = serialization.load_pem_private_key(pem_data, None)

with open("pki/cert_user.pem", "rb") as c:
    pem_data = c.read()
cert_user = x509.load_pem_x509_certificate(pem_data)

with open("pki/cert_ch.pem", "rb") as c:
    cert_ch_pem = c.read()

with open("ids/CH_ID.id", "rb") as c:
    chid = c.read()
    
with open("sn.prp", "rb") as r:
    sn = int.from_bytes(r.read())

with open("DeviceDB.db", "rb") as h:
    db = h.read()
        
with open("rules.prp", "rb") as r:
    rule = r.read()
    
while True:
    try:
        with open("token.prp", "rb") as h:
            token = h.read()
    except FileNotFoundError:
        time.sleep(2)
        continue
    time.sleep(1)
    print("New license registered. Beginning monitoring.")