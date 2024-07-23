from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding

def xor_bytes(s1, s2):
    res = []
    for i in range(min(len(s1),len(s2))):
        res.append(s1[i] ^ s2[i])

    return bytes(res)

def acquire_license():
    # 1. SEND (TID || ContentID) to LicenseServer
    # 1.1 Compute T_U from private key r_U via ECDH
    temp_sk = ec.generate_private_key(ec.SECP384R1())
    temp_pk = temp_sk.public_key()
    
    with open("pki/cert_ls.pem", "rb") as c:
        pem_data = c.read()
    cert_ls = x509.load_pem_x509_certificate(pem_data)    
    
    # 1.2 Compute TID
    with open("ids/D_ID.id", "rb") as h:
        did = h.read()
    
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


    # 3. SEND ({Sig_U( H(T_U || T_LS || License) || token )}_K)

