# IMPORTS
import datetime
import os
import time
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import ec, padding

def xor_bytes(s1, s2):
    res = []
    for i in range(min(len(s1),len(s2))):
        res.append(s1[i] ^ s2[i])

    return bytes(res)

# LOAD FROM FILES
with open("pki/sk_ls.pem", "rb") as h:
    pem_data = h.read()
sk_ls = serialization.load_pem_private_key(pem_data)

with open("pki/cert_user.pem", "rb") as c:
    pem_data = c.read()
cert_user = x509.load_pem_x509_certificate(pem_data)

with open("pki/cert_ls.pem", "rb") as c:
    cert_ls_pem = c.read()

with open("ids/LS_ID.id", "rb") as c:
    lsid = c.read()
    
with open("sn.prp", "rb") as r:
    sn = int.from_bytes(r.read())

# LISTEN FOR LICENSE REQUESTS
while True:
    try:
        # RECEIVE (TID || ContentID)
        with open("comms/ls.msg", "rb") as h:
            msg = h.read()
        os.remove("comms/ls.msg")
        tid_enc, contentid = msg[:64], msg[64:]
        
        tid = sk_ls.decrypt(
            ciphertext = tid_enc,
            padding = padding.OAEP(
                mgf = padding.MGF1(algorithm=hashes.SHA256()),
                algorithm = hashes.SHA256(),
            )
        )
        
        temp_pk_user = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1, tid[:32])
        
        did = xor_bytes(tid[:32], tid[32:])
        
        # CHECK DID
        with open("DeviceDB.db", "rb") as h:
            db = h.read()
        if not(did in db):
            print("ERROR: Device not registered!")
            exit(1)
        
        # SEND (T_LS || r || {Sig_LS( H(r || T-LS || T_U) || PK_U(License) || ContentID ) || Cert_LS}_K) 
        # to LicenseAgent
        temp_sk = ec.generate_private_key(ec.SECP256R1())   # r_LS
        temp_pk = temp_sk.public_key()                      # T_LS
        nonce = os.urandom(32)                              # r
        
        shared = temp_sk.exchange(ec.ECDH, temp_pk_user)
        digest = hashes.Hash(hashes.SHA256())
        digest.update(shared + nonce)
        k = digest.finalize()                               # K
        
        digest.update(nonce + temp_pk + temp_pk_user)
        exchange_hash = digest.finalize()
        
        digest.update(did + lsid)
        kid = digest.finalize()
        
        with open("rules.prp", "rb") as r:
            rule = r.read()                                 # Usagerule; for showcase purposes
        
        date = datetime.datetime.now(datetime.UTC)
        
        other_data = bytes(32)
        
        license = sn.to_bytes(32, "big") + date + rule + other_data
        digest.update(license)
        license += sk_ls.sign(digest.finalize(), ec.ECDSA)
        lic_enc = cert_user.public_key().encrypt(
            plaintext = license,
            padding = padding.OAEP(
                mgf = padding.MGF1(algorithm=hashes.SHA256()),
                algorithm = hashes.SHA256(),
            )
        )
        
        aesgcm = AESGCM(k)
        sym_pt = sk_ls.sign(exchange_hash + lic_enc + contentid, ec.ECDSA) + cert_ls_pem
        
        response = temp_pk.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo) + nonce + aesgcm.encrypt(nonce, sym_pt, None)
        
        with open("comms/la.msg", "wb") as h:
            h.write(response)
                     
        # RECEIVE ({Sig_U( H(T_U || T_LS || License) || token )}_K), if successful INCREASE SN
        
    except FileNotFoundError:
        time.sleep(2)
        continue
