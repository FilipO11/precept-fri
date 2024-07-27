import os, sys, time, base64
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

def acquire_license():
    with open("pki/sk_user.pem", "rb") as h:
        pem_data = h.read()
    sk_user = serialization.load_pem_private_key(pem_data, None)
    with open("ids/D_ID.id", "rb") as h:
        did = h.read()
    with open("pki/cert_ls.pem", "rb") as c:
        pem_data = c.read()
    cert_ls = x509.load_pem_x509_certificate(pem_data)    
    
    print("Computing request...")
    
    # SEND (TID || ContentID) to LicenseServer
    temp_sk = ec.generate_private_key(ec.SECP256K1())
    temp_pk = temp_sk.public_key()
    temp_pk_pem = temp_pk.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    did = did + bytes(142)

    tid = cert_ls.public_key().encrypt(
        plaintext = temp_pk_pem + xor_bytes(temp_pk_pem, did),
        padding = padding.OAEP(
            mgf = padding.MGF1(algorithm=hashes.SHA256()),
            algorithm = hashes.SHA256(),
            label=None
        )
    )
    
    with open("ids/Content_ID.id", "rb") as h:
        contentid = h.read()
    
    with open("comms/ls.msg", "wb") as h:
        h.write(contentid + tid)
    
    print("Request sent.\nWaiting for response...")

    # RECEIVE (T_LS || r || {Sig_LS( H(r || T-LS || T_U) || PK_U(License) || ContentID ) || Cert_LS}_K)
    response = None
    while response == None:
        try:
            with open("comms/la.msg", "rb") as h:
                response = h.read()
        except FileNotFoundError:
            time.sleep(1)
            continue
    os.remove("comms/la.msg")
    print("Response received.\nProcessing response...")
    temp_pk_ls, nonce, sym_ct = response[:174], response[174:206], response[206:]
    
    temp_pk_ls = serialization.load_pem_public_key(temp_pk_ls)
    
    shared = temp_sk.exchange(ec.ECDH(), temp_pk_ls)
    digest = hashes.Hash(hashes.SHA256())
    digest.update(shared + nonce)
    k = base64.urlsafe_b64encode(digest.finalize())
    
    f = Fernet(k)
    sym_pt = f.decrypt(sym_ct)
    exchange_hash, license = sym_pt[:32], sym_pt[32:602]
    
    try:
        print("Checking license signature...")
        lic_sig = license[58:]
        cert_ls.public_key().verify(
            lic_sig,
            license[:58],
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        print("Signature verified.\nComputing confirmation...")
    except InvalidSignature:
        print("ERROR: Invalid license signature.")
        exit(1)
    
    digest = hashes.Hash(hashes.SHA256())
    digest.update(nonce 
                  + temp_pk_ls.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
                  + temp_pk.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
                  )
    check_exchange_hash = digest.finalize()
    
    if exchange_hash != check_exchange_hash:
        print("ERROR: Invalid exchange hash.")
        exit(1)
    
    # SEND ({Sig_U( H(T_U || T_LS || License) || token )}_K)
    digest = hashes.Hash(hashes.SHA256())
    digest.update(did + license)
    token = digest.finalize()
    
    confirmation_hash = sk_user.sign(
        temp_pk.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo) 
        + temp_pk_ls.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        + license, 
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    
    print("hash: ", len(confirmation_hash))
    print("token: ", len(token))
    confirm_license = f.encrypt(confirmation_hash + token)
    
    with open("comms/ls.msg", "wb") as h:
        h.write(confirm_license)
    
    with open("lic.prp", "wb") as h:
        h.write(license)
    
    # CREATE USAGE RECORD
    with open("usedata.prp", "wb") as h: 
        h.write(os.urandom(256))

try:
    with open("lic.prp", "rb") as h:
        license = h.read()
except FileNotFoundError:
    print("No license found. Issuing request.")
    acquire_license()
print("License acquired. Proceeding in idle mode.")

with open("lic.prp", "rb") as h:
    license = h.read()
with open("token.prp", "rb") as h:
    token = h.read()
with open("pki/sk_user.pem", "rb") as h:
    pem_data = h.read()
sk_user = serialization.load_pem_private_key(pem_data, None)
with open("pki/cert_ch.pem", "rb") as c:
    pem_data = c.read()
cert_ch = x509.load_pem_x509_certificate(pem_data)
with open("ids/D_ID.id", "rb") as h:
    did = h.read()

while True:
    request = None
    while request == None:
        try:
            with open("comms/la.msg", "rb") as h:
                request = h.read()
        except FileNotFoundError:
            time.sleep(1)
            continue
    os.remove("comms/la.msg")
    print("Request received.\nProcessing request...")
    
    request = sk_user.decrypt(
        ciphertext = request,
        padding = padding.OAEP(
            mgf = padding.MGF1(algorithm=hashes.SHA256()),
            algorithm = hashes.SHA256(),
            label=None
        )
    )
    token_ch, chid, temp_pk_ch = request[:32], request[32:64], serialization.load_pem_public_key(request[64:])
    
    if token_ch != token:
        print("ERROR: Invalid token.")
        exit(1)
    
    temp_sk = ec.generate_private_key(ec.SECP256K1())
    temp_pk = temp_sk.public_key()
    nonce = os.urandom(32)
    
    shared = temp_sk.exchange(ec.ECDH(), temp_pk_ch)
    digest = hashes.Hash(hashes.SHA256())
    digest.update(shared + nonce)
    k = base64.urlsafe_b64encode(digest.finalize())
    
    digest = hashes.Hash(hashes.SHA256())
    digest.update(temp_pk_ch.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
                  + temp_pk.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
                  + nonce
                  )
    exchange_hash = digest.finalize()
    
    with open("usedata.prp", "rb") as h:
        usedata = h.read()
    
    usedata_enc = cert_ch.public_key().encrypt(
        plaintext = request,
        padding = padding.OAEP(
            mgf = padding.MGF1(algorithm=hashes.SHA256()),
            algorithm = hashes.SHA256(),
            label=None
        )
    )
    
    sig = sk_user.sign(
        exchange_hash + usedata_enc, 
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    
    f = Fernet(k)
    pt = exchange_hash + usedata_enc + sig + token_ch
    
    response = (temp_pk.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
                + nonce
                + f.encrypt(pt)
                )
    
    with open("comms/ch.msg", "wb") as h:
        h.write(response)
    
    print("Usage data sent.\nWaiting for confirmation...")
    
    confirmation = None
    while confirmation == None:
        try:
            with open("comms/la.msg", "rb") as h:
                confirmation = h.read()
        except FileNotFoundError:
            time.sleep(2)
            continue
    os.remove("comms/la.msg")
    print("Confirmation received.\nProcessing confirmation...")
    
    confirmation = f.decrypt(confirmation)
    confirmation_hash, confhash_sig = confirmation[:32], confirmation[32:]
        
    try:
        print("Checking license signature...")
        cert_ch.public_key().verify(
            confhash_sig,
            confirmation_hash,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
    except InvalidSignature:
        print("ERROR: Invalid confirmation signature.")
        continue
    print("Confirmation verified. Proceeding in idle mode.")