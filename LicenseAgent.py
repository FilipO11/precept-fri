import os
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import ec, padding

def xor_bytes(s1, s2):
    res = []
    for i in range(min(len(s1),len(s2))):
        res.append(s1[i] ^ s2[i])

    return bytes(res)

def acquire_license():
    with open("pki/sk_user.pem", "rb") as h:
        pem_data = h.read()
    sk_user = serialization.load_pem_private_key(pem_data)
    with open("ids/D_ID.id", "rb") as h:
        did = h.read()
    with open("pki/cert_ls.pem", "rb") as c:
        pem_data = c.read()
    cert_ls = x509.load_pem_x509_certificate(pem_data)    
    
    # 1. SEND (TID || ContentID) to LicenseServer
    # 1.1 Compute T_U from private key r_U via ECDH
    temp_sk = ec.generate_private_key(ec.SECP256K1())
    temp_pk = temp_sk.public_key()
        
    # 1.2 Compute TID
    tid = cert_ls.public_key().encrypt(
        plaintext = temp_pk.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo) 
                    + xor_bytes(temp_pk.public_bytes(), did),
        padding = padding.OAEP(
            mgf = padding.MGF1(algorithm=hashes.SHA256()),
            algorithm = hashes.SHA256(),
        )
    )
    
    # 1.3 Get ContentID
    with open("ids/Content_ID.id", "rb") as h:
        contentid = h.read()
    
    # 1.3 Send license request
    with open("comms/ls.msg", "wb") as h:
        h.write(tid + contentid)

    # 2. RECEIVE (T_LS || r || {Sig_LS( H(r || T-LS || T_U) || PK_U(License) || ContentID ) || Cert_LS}_K)
    with open("comms/la.msg", "rb") as h:
        msg = h.read()
    os.remove("comms/la.msg")
    temp_pk_ls, nonce, sym_ct = msg[:32], msg[32:64], msg[64:]
    
    temp_pk_ls = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1, temp_pk_ls)
    
    shared = temp_sk.exchange(ec.ECDH, temp_pk_ls)
    digest = hashes.Hash(hashes.SHA256())
    digest.update(shared + nonce)
    k = digest.finalize()
    
    # decrypt aesgcm
    aesgcm = AESGCM(k)
    sym_pt = aesgcm.decrypt(nonce, sym_ct, None)
    sig, lic_enc = sym_pt[:64], sym_pt[64:]
    
    license = sk_user.decrypt(
        ciphertext = lic_enc,
        padding = padding.OAEP(
            mgf = padding.MGF1(algorithm=hashes.SHA256()),
            algorithm = hashes.SHA256(),
        )
    )
    #TODO: verify license signature
    
    digest.update(nonce + temp_pk_ls + temp_pk)
    exchange_hash = digest.finalize()
    
    # verify sig via cert_ls
    try:
        cert_ls.public_key().verify(
            sig,
            exchange_hash + lic_enc + contentid,
            ec.ECDSA
        )
    except InvalidSignature:
        print("ERROR: Invalid license server response signature.")
        exit(1)
    # verify exc hash (SKIP FOR NOW)
    
    # 3. SEND ({Sig_U( H(T_U || T_LS || License) || token )}_K)

