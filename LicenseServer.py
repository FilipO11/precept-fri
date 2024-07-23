# IMPORTS
import os
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding

def xor_bytes(s1, s2):
    res = []
    for i in range(min(len(s1),len(s2))):
        res.append(s1[i] ^ s2[i])

    return bytes(res)

# LOAD KEYS and CERT
with open("keys/LS_private_key.key", "rb") as h:
    LS_serialized_private = h.read()
LS_private_key = serialization.load_pem_private_key(
    LS_serialized_private,
    password=b'preceptFRI',
)

with open("keys/LS_public_key.key", "rb") as h:
    LS_serialized_public = h.read()
LS_public_key = serialization.load_pem_public_key(LS_serialized_public,)

# LISTEN FOR LICENSE REQUESTS
while True:
    try:
        # 1. RECEIVE (TID || ContentID)
        with open("comms/ls.msg", "rb") as h:
            msg = h.read()
        os.remove("comms/ls.msg")
        tid_enc, contentid = msg[:64], msg[64:]
        
        tid = LS_private_key.decrypt(
            ciphertext = tid_enc,
            padding = padding.OAEP(
                mgf = padding.MGF1(algorithm=hashes.SHA256()),
                algorithm = hashes.SHA256(),
            )
        )
        
        LA_public_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP384R1, tid[:32])
        
        did = xor_bytes(tid[:32], tid[32:])
        
        # CHECK DID
        with open("DeviceDB.db", "rb") as h:
            db = h.read()
        if not(did in db):
            print("ERROR: Device not registered!")
            exit(1)
        
        # SEND (T_LS || r || {Sig_LS( H(r || T-LS || T_U) || PK_U(License) || ContentID ) || Cert_LS}_K) 
        # to LicenseAgent

        # RECEIVE ({Sig_U( H(T_U || T_LS || License) || token )}_K)
        
    except FileNotFoundError:
        # time.sleep(2)
        continue
