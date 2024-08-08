# IMPORTS
import datetime, os, time, base64, threading, pickle
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

def client_thread(msg):
    with open("sn.prp", "rb") as r:
        sn = int.from_bytes(r.read())

    with open("DeviceDB.db", "rb") as dbfile:
        db = pickle.load(dbfile)
            
    with open("rules.prp", "rb") as r:
        rule = r.read()
    
    contentid, tid_enc = msg[:32], msg[32:]
        
    tid = sk_ls.decrypt(
        ciphertext = tid_enc,
        padding = padding.OAEP(
            mgf = padding.MGF1(algorithm=hashes.SHA256()),
            algorithm = hashes.SHA256(),
            label=None
        )
    )
    
    temp_pk_user = serialization.load_pem_public_key(tid[:174])
    did = xor_bytes(tid[:174], tid[174:])
    did = did[:32]
    
    # CHECK DID
    if not(did in db):
        print("ERROR: Device not registered!")
        exit(1)
    
    # SEND (T_LS || r || {Sig_LS( H(r || T-LS || T_U) || PK_U(License) || ContentID ) || Cert_LS}_K)
    temp_sk = ec.generate_private_key(ec.SECP256K1())
    temp_pk = temp_sk.public_key()
    nonce = os.urandom(32)
    
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
    
    license = sn.to_bytes(8, "big") + date + rule + other_data
    sig_lic = sk_ls.sign(
        license, 
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    license += sig_lic
    
    f = Fernet(k)
    pt = exchange_hash + license + contentid + cert_ls_pem
            
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
    
    db[did] = token
    with open("Device.db", "wb") as dbfile:
        pickle.dump(db, dbfile)
    
    sn += 1
    with open("sn.prp", "wb") as h:
        h.write(sn.to_bytes(8, "big"))

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

# LISTEN FOR LICENSE REQUESTS
while True:
    print("Waiting for license request...")
    try:
        # RECEIVE (TID || ContentID)
        with open("comms/ls.msg", "rb") as h:
            msg = h.read()
        os.remove("comms/ls.msg")
        print("License request received.\nPreparing response...")
        thread = threading.Thread(target=client_thread, args=(msg))
        thread.daemon = True
        thread.start()
        
    except FileNotFoundError:
        time.sleep(2)
        continue
