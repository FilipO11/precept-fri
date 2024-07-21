from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding

def xor_bytes(s1, s2):
    """Izvede operacijo XOR med podanima seznamoma bajtov in vrne seznam bajtov"""
    res = []
    for i in range(min(len(s1),len(s2))):
        res.append(s1[i] ^ s2[i])

    return bytes(res)

def acquire_license():
    # 1. SEND (TID || ContentID) to LicenseServer
    # 1.1 Compute T_U from private key r_U via ECDH
    LA_private_key = ec.generate_private_key(ec.SECP384R1())
    LA_public_key = LA_private_key.public_key()
    
    with open("keys/LS_public_key.key", "rb") as h:
        LS_serialized_public = h.read()
    LS_public_key = serialization.load_pem_public_key(LS_serialized_public,)
    
    # 1.2 Compute TID
    with open("ids/D_ID.id", "rb") as h:
        did = h.read()
    
    tid = LS_public_key.encrypt(
        plaintext=LA_public_key+xor_bytes(LA_public_key.public_bytes(), did),
        padding=padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
        )
    )
    
    # 1.3 Send TID
    with open("comms/ls.msg", "wb") as h:
        h.write(tid)

    # 2. RECEIVE (T_LS || r || {Sig_LS( H(r || T-LS || T_U) || PK_U(License) || ContentID ) || Cert_LS}_K)


    # 3. SEND ({Sig_U( H(T_U || T_LS || License) || token )}_K)

