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
with open("pki/sk_ls.pem", "rb") as h:
    pem_data = h.read()
sk_ls = serialization.load_pem_private_key(pem_data, None)

with open("pki/cert_user.pem", "rb") as c:
    pem_data = c.read()
cert_user = x509.load_pem_x509_certificate(pem_data)

with open("pki/cert_ls.pem", "rb") as c:
    cert_ls_pem = c.read()

with open("ids/LS_ID.id", "rb") as c:
    lsid = c.read()
    
with open("sn.prp", "rb") as r:
    sn = int.from_bytes(r.read())

with open("DeviceDB.db", "rb") as h:
    db = h.read()
        
with open("rules.prp", "rb") as r:
    rule = r.read()                                 # Usagerule; for showcase purposes


# LISTEN FOR LICENSE REQUESTS
while True:
    try:
        print("Waiting for license request...")
        # RECEIVE (TID || ContentID)
        with open("comms/ls.msg", "rb") as h:
            msg = h.read()
        os.remove("comms/ls.msg")
        contentid, tid_enc = msg[:32], msg[32:]
        
        tid = sk_ls.decrypt(
            ciphertext = tid_enc,
            padding = padding.OAEP(
                mgf = padding.MGF1(algorithm=hashes.SHA256()),
                algorithm = hashes.SHA256(),
                label=None
            )
        )
        
        # print("tid: \n", tid.hex())
        
        temp_pk_user = serialization.load_pem_public_key(tid[:174])
        # print("xor: \n", tid[174:].hex())
        
        did = xor_bytes(tid[:174], tid[174:])
        
        # print("did: \n", did.hex())
        did = did[:32]
        
        # CHECK DID
        if not(did in db):
            print("ERROR: Device not registered!")
            exit(1)
        
        # SEND (T_LS || r || {Sig_LS( H(r || T-LS || T_U) || PK_U(License) || ContentID ) || Cert_LS}_K) 
        # to LicenseAgent
        temp_sk = ec.generate_private_key(ec.SECP256K1())   # r_LS
        temp_pk = temp_sk.public_key()                      # T_LS
        nonce = os.urandom(32)                              # r
        
        shared = temp_sk.exchange(ec.ECDH(), temp_pk_user)
        digest = hashes.Hash(hashes.SHA256())
        digest.update(shared + nonce)
        k = base64.urlsafe_b64encode(digest.finalize())
        
        digest = hashes.Hash(hashes.SHA256())
        digest.update(nonce 
                      + temp_pk.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
                      + temp_pk_user.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
                      )
        exchange_hash = digest.finalize()
        
        digest = hashes.Hash(hashes.SHA256())
        digest.update(did + lsid)
        kid = digest.finalize()
        
        date = datetime.date.today().isoformat().encode("utf-8")
        
        other_data = bytes(32)
        
        # print("sn: ", len(sn.to_bytes(32, "big")))
        # print("date: ", len(date))
        # print("rule: ", len(rule))
        # print("other_date: ", len(other_data))
        
        license = sn.to_bytes(8, "big") + date + rule + other_data
        # digest = hashes.Hash(hashes.SHA256())
        # digest.update(license)
        sig_lic = sk_ls.sign(
            license, 
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        # print("lic: ", len(license))
        license += sig_lic
        # print("sig: ", len(sig_lic))
        # print("full: ", len(license))
        # print("key: ", sk_ls.key_size)
        
        f = Fernet(k)
        pt = exchange_hash + license + contentid + cert_ls_pem
        
        # print("lic: ", len(temp_pk.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)))
        # print("sig: ", len(sig_lic))
        # print("full: ", len(license + sig_lic))
                
        response = temp_pk.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo) + nonce + f.encrypt(pt)
        
        with open("comms/la.msg", "wb") as h:
            h.write(response)
        
        print("Issued license.\nWaiting for confirmation...")
        
        # RECEIVE ({Sig_U( H(T_U || T_LS || License) || token )}_K), if successful INCREASE SN
        confirmation = None
        while confirmation == None:
            try:
                with open("comms/ls.msg", "rb") as h:
                    confirmation = h.read()
            except FileNotFoundError:
                time.sleep(1)
                continue
        os.remove("comms/ls.msg")
        print("Confirmation received.")
        pt = f.decrypt(confirmation, None)
        confirmation_hash, token = pt[:512], pt[512:]
        
        try:
            print("Checking confirmation...")
            cert_user.public_key().verify(
                confirmation_hash,
                temp_pk_user.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
                + temp_pk.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
                + license,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            print("Confirmation verified.\nFinalizing...")
        except InvalidSignature:
            print("ERROR: Invalid license signature.")
            exit(1)
        
        with open("token.prp", "wb") as h:
            h.write(token)
        
        sn += 1
        with open("sn.prp", "wb") as h:
            h.write(sn.to_bytes(8, "big"))
        
    except FileNotFoundError:
        time.sleep(2)
        continue
