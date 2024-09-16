import os, base64, requests, asyncio, websockets
from cryptography import x509
from cryptography.fernet import Fernet
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding

LICENSESERVER = "localhost:8000"
ACQUISITIONURI = "http://"+LICENSESERVER+"/acqlic" 
TRACKINGURI = "ws://"+LICENSESERVER+"/tracking"

def xor_bytes(s1, s2):
    res = []
    for i in range(min(len(s1),len(s2))):
        res.append(s1[i] ^ s2[i])

    return bytes(res)

def acquire_license():
    with open("ids/Content_ID.id", "rb") as h:
        contentid = h.read()
    with open("pki/sk_user.pem", "rb") as h:
        pem_data = h.read()
    sk_user = serialization.load_pem_private_key(pem_data, None)
    with open("ids/D_ID.id", "rb") as h:
        did = h.read()
    with open("pki/cert_ls.pem", "rb") as c:
        pem_data = c.read()
    cert_ls = x509.load_pem_x509_certificate(pem_data)
    
    print("Computing request...")
    
    # 1. Generate exchange keys and pad DeviceID
    temp_sk = ec.generate_private_key(ec.SECP256K1())
    temp_pk = temp_sk.public_key()
    temp_pk_pem = temp_pk.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    did = did + bytes(142) # DeviceID needs to be padded to the length of the serialized temporary public key - 174 bytes

    # 2. Calculate TID as asymetrically encrypted (T_U, T_U ^ DID)
    tid = cert_ls.public_key().encrypt(
        plaintext = temp_pk_pem + xor_bytes(temp_pk_pem, did),
        padding = padding.OAEP(
            mgf = padding.MGF1(algorithm=hashes.SHA256()),
            algorithm = hashes.SHA256(),
            label=None
        )
    )
    
    # 3. Assemble request
    request = {
        "type": "request",
        "body": (contentid + tid).hex()
    }
    
    print("Request sent.\nWaiting for response...")
    response_obj = requests.post(ACQUISITIONURI, json=request)
    response = bytes.fromhex(response_obj.json()["response"])
    print("Response received.\nProcessing response...")

    # 4. Unpack response
    temp_pk_ls, nonce, sym_ct = response[:174], response[174:206], response[206:]
    temp_pk_ls = serialization.load_pem_public_key(temp_pk_ls)
    
    # 5. Derive session key
    shared = temp_sk.exchange(ec.ECDH(), temp_pk_ls)
    digest = hashes.Hash(hashes.SHA256())
    digest.update(shared + nonce)
    k = base64.urlsafe_b64encode(digest.finalize())
    
    # 6. Decrypt asymetric ciphertext and unpack it
    f = Fernet(k)
    sym_pt = f.decrypt(sym_ct)
    exchange_hash, license, license_k, contentid, sig_fer = sym_pt[:32], sym_pt[32:920], sym_pt[920:1432], sym_pt[1432:1464], sym_pt[1464:1976]
    
    # 7. Verify response signature
    try:
        print("Checking response signature...")
        cert_ls.public_key().verify(
            sig_fer,
            sym_pt[:1464],
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        print("Signature verified.\nComputing confirmation...")
    except InvalidSignature:
        print("ERROR: Invalid response signature.")
        exit(1) # SHOULD BE HANDLED
    
    # 8. Asymetrically decrypt hybrid cipher key, then decrypt license
    license_k = sk_user.decrypt(
        ciphertext = license_k,
        padding = padding.OAEP(
            mgf = padding.MGF1(algorithm=hashes.SHA256()),
            algorithm = hashes.SHA256(),
            label=None
        )
    )
    
    lic_f = Fernet(license_k)
    license = lic_f.decrypt(license)
    
    # 9. Verify license signature
    try:
        print("Checking license signature...")
        lic_sig = license[90:]
        cert_ls.public_key().verify(
            lic_sig,
            license[:90],
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        print("Signature verified.\nComputing confirmation...")
    except InvalidSignature:
        print("ERROR: Invalid license signature.")
        exit(1) # SHOULD BE HANDLED
    
    # 10. Calculate exchange hash and verify it
    digest = hashes.Hash(hashes.SHA256())
    digest.update(nonce 
                  + temp_pk_ls.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
                  + temp_pk.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
                  )
    check_exchange_hash = digest.finalize()
    
    if exchange_hash != check_exchange_hash:
        print("ERROR: Invalid exchange hash.")
        exit(1)
    
    # 11. Calculate token
    digest = hashes.Hash(hashes.SHA256())
    digest.update(did + license)
    token = digest.finalize()
    
    # 12. Calculate and sign the confirmation hash
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
    
    # 13. Encrypt the confirmation plaintext
    confirm_license = f.encrypt(confirmation_hash + token)
    
    # 14. Assemble the confirmation
    confirmation = {
        "type": "confirmation",
        "body": confirm_license.hex()
    }
    requests.post(ACQUISITIONURI, json=confirmation)
    
    # 15. Record persistent values
    with open("lic.prp", "wb") as h:
        h.write(license)
        
    with open("token.prp", "wb") as h:
        h.write(token)
    
    # CREATE USAGE DATA FOR SIMULATION PURPOSES
    with open("usedata.prp", "wb") as h: 
        h.write(os.urandom(256))
    
    return True

async def tracking():
    # 1. Connect to Clearinghouse
    async with websockets.connect(TRACKINGURI) as ws:
        while True:
            request = await ws.recv()
            print("Request received.\nProcessing request...")

            # 2. Decrypt and unpack request
            request = sk_user.decrypt(
                ciphertext = request,
                padding = padding.OAEP(
                    mgf = padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm = hashes.SHA256(),
                    label=None
                )
            )
            token_ch, chid, temp_pk_ch = request[:32], request[32:64], serialization.load_pem_public_key(request[64:])

            # 3. Verify received token
            if token_ch != token:
                print("ERROR: Invalid token.")
                exit(1)

            # 4. Generate exchange keys and nonce
            temp_sk = ec.generate_private_key(ec.SECP256K1())
            temp_pk = temp_sk.public_key()
            nonce = os.urandom(32)

            # 5. Derive session key
            shared = temp_sk.exchange(ec.ECDH(), temp_pk_ch)
            digest = hashes.Hash(hashes.SHA256())
            digest.update(shared + nonce)
            k = base64.urlsafe_b64encode(digest.finalize())

            # 6. Calculate exchange hash
            digest = hashes.Hash(hashes.SHA256())
            digest.update(temp_pk_ch.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
                          + temp_pk.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
                          + nonce
                          )
            exchange_hash = digest.finalize()

            # 7. Load usage data
            with open("usedata.prp", "rb") as h:
                usedata = h.read()

            # 8. Asymetrically encrypt license via hybrid cipher
            usedata_enc_k = Fernet.generate_key()
            ud_f = Fernet(usedata_enc_k)
            usedata_enc = ud_f.encrypt(usedata)
            
            usedata_enc_k = cert_ch.public_key().encrypt(
                plaintext = usedata_enc_k,
                padding = padding.OAEP(
                    mgf = padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm = hashes.SHA256(),
                    label=None
                )
            )

            # 9. Sign exchange hash and (encrypted) usage data
            sig = sk_user.sign(
                exchange_hash + usedata_enc, 
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )

            # 10. Assemble symetric plaintext
            f = Fernet(k)
            pt = (
                exchange_hash 
                  + usedata_enc_k 
                  + sig 
                  + token_ch
                  + usedata_enc
            )

            # 11. Assemble response
            response = (temp_pk.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
                        + nonce
                        + f.encrypt(pt)
                        )

            await ws.send(response)
            print("Usage data sent.\nWaiting for confirmation...")

            confirmation = await ws.recv()
            print("Confirmation received.\nProcessing confirmation...")

            # 12. Decrypt confirmation
            confirmation = f.decrypt(confirmation)
            
            # 13. Verify confirmation
            try:
                print("Checking confirmation signature...")
                cert_ch.public_key().verify(
                    confirmation,
                    temp_pk_ch.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
                    + temp_pk.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
                    + k
                    + usedata,
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

if __name__ == "__main__":
    # TRY TO OPEN LICENSE, REQUEST IF NOT FOUND
    license = None
    while license is None:
        try:
            with open("lic.prp", "rb") as h:
                license = h.read()
        except FileNotFoundError:
            print("No license found. Issuing request.")
            acquire_license()
        print("License acquired. Proceeding in idle mode.")

    # LOAD FROM FILES
    try:
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
    except FileNotFoundError as e:
        print("File system error. Could not load data from " + e.filename)

    asyncio.run(tracking())
