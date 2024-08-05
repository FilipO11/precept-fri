# IMPORTS
import datetime, os, time, base64, threading, socket, struct
from cryptography import x509
from cryptography.fernet import Fernet
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding

PORT = 50000
HEADER_LENGTH = 2

def xor_bytes(s1, s2):
    res = []
    for i in range(min(len(s1),len(s2))):
        res.append(s1[i] ^ s2[i])

    return bytes(res)

def receive_fixed_length_msg(sock, msglen):
    message = b''
    while len(message) < msglen:
        chunk = sock.recv(msglen - len(message))
        if chunk == b'':
            raise RuntimeError("socket connection broken")
        message = message + chunk

    return message

def receive_message(sock):
    header = receive_fixed_length_msg(sock,
                                      HEADER_LENGTH)
    message_length = struct.unpack("!H", header)[0]

    message = None
    if message_length > 0:
        message = receive_fixed_length_msg(sock, message_length)

    return message

def send_message(sock, message):
    header = struct.pack("!H", len(message))

    message = header + message
    sock.sendall(message)

def client_thread(client_sock, client_addr):
    global clients, sn
    
    print("[system] connected with " + client_addr[0] + ":" + str(client_addr[1]))
    print("[system] we now have " + str(len(clients)) + " clients")
    
    msg = receive_message(client_sock)
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
    
    send_message(client_sock, response)
    print("Issued license to " + client_addr[0] + ":" + str(client_addr[1])+".\nWaiting for confirmation...")
    
    # RECEIVE ({Sig_U( H(T_U || T_LS || License) || token )}_K), if successful INCREASE SN
    confirmation = receive_message(client_sock)
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
    rule = r.read()

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(("localhost", PORT))
server_socket.listen(1)

# LISTEN FOR LICENSE REQUESTS
print("Waiting for license request...")
clients = set()
clients_lock = threading.Lock()
while True:
    try:
        client_sock, client_addr = server_socket.accept()
        with clients_lock:
            clients.add(client_sock)
        print("License request received.\nPreparing response...")
        thread = threading.Thread(target=client_thread, args=(client_sock, client_addr))
        thread.daemon = True
        thread.start()
        
    except KeyboardInterrupt:
        break

print("Closing server socket ...")
server_socket.close()