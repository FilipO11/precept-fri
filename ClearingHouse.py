# IMPORTS
import os, time, base64, pickle
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

with open("DeviceDB.db", "rb") as dbfile:
    db = pickle.load(dbfile)
        
with open("rules.prp", "rb") as r:
    rule = r.read()

token = None
while token == None:
    # WAIT FOR DEVICE TO BE LICENSED
    for device in db:
        if db[device] != b'': 
            token = db[device]
            break
        else: time.sleep(2)

time.sleep(1)

while True:
    print("Registered licenses detected.\nRequesting usage data...")
    
    # SEND USAGE DATA REQUEST
    temp_sk = ec.generate_private_key(ec.SECP256K1())
    temp_pk = temp_sk.public_key()
    
    request = (token 
                + chid 
                + temp_pk.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
                )
    
    request = cert_user.public_key().encrypt(
        plaintext = request,
        padding = padding.OAEP(
            mgf = padding.MGF1(algorithm=hashes.SHA256()),
            algorithm = hashes.SHA256(),
            label=None
        )
    )
    
    with open("comms/la.msg", "wb") as h:
        h.write(request)
    
    print("Usage data request sent.\nWaiting for data...")
    
    response = None
    while response == None:
        try:
            with open("comms/ch.msg", "rb") as h:
                response = h.read()
        except FileNotFoundError:
            time.sleep(2)
            continue
    os.remove("comms/ch.msg")
    print("Data received.\nProcessing response...")
    
    temp_pk_user, nonce, sym_ct = response[:174], response[174:206], response[206:]
    temp_pk_user = serialization.load_pem_public_key(temp_pk_user)
    
    shared = temp_sk.exchange(ec.ECDH(), temp_pk_user)
    digest = hashes.Hash(hashes.SHA256())
    digest.update(shared + nonce)
    k = base64.urlsafe_b64encode(digest.finalize())
    
    f = Fernet(k)
    sym_pt = f.decrypt(sym_ct)
    
    exchange_hash, usedata_enc, datasig = sym_pt[:32], sym_pt[32:544], sym_pt[544:1056]
    
    digest = hashes.Hash(hashes.SHA256())
    digest.update(temp_pk.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
                  + temp_pk_user.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
                  + nonce
                  )
    
    if exchange_hash != digest.finalize():
        print("ERROR: Invalid exchange hash.")
        exit(1) # SHOULD BE CONTINUE OR SOMETHING
    
    try:
        print("Checking response signature...")
        cert_user.public_key().verify(
            datasig,
            exchange_hash + usedata_enc,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
    except InvalidSignature:
        print("ERROR: Invalid response signature.")
        exit(1)
    
    usedata = sk_ch.decrypt(
        ciphertext = usedata_enc,
        padding = padding.OAEP(
            mgf = padding.MGF1(algorithm=hashes.SHA256()),
            algorithm = hashes.SHA256(),
            label=None
        )
    )
    
    print("Response verified.\nPreparing confirmation...")
    digest = hashes.Hash(hashes.SHA256())
    digest.update(temp_pk.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
                  + temp_pk_user.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
                  + k
                  + usedata
                  )
    confirmation_hash = digest.finalize()
    
    sig = sk_ch.sign(
        confirmation_hash, 
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    
    confirmation = f.encrypt(confirmation_hash + sig)
    
    with open("comms/la.msg", "wb") as h:
        h.write(confirmation)
    
    print("Confirmation sent.\nStarting next cycle...")
    time.sleep(5)
    