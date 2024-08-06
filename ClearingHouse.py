# IMPORTS
import os, time, base64, struct, socket, threading
from cryptography import x509
from cryptography.fernet import Fernet
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding

PORT = 50001
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

def poll_client(client_sock, client_addr):
    global clients
    
    print("[CH] connected with " + client_addr[0] + ":" + str(client_addr[1]))
    print("[CH] we now have " + str(len(clients)) + " clients")
    
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
    
    send_message(client_sock, request)
    print("Usage data request sent.\nWaiting for data...")
    
    response = receive_message(client_sock)
    print("Data received.\nCalculating confirmation...")
    
    temp_pk_user, nonce, sym_ct = response[:174], response[174:206], response[206:]
    temp_pk_user = serialization.load_pem_public_key(temp_pk_user)
    
    shared = temp_sk.exchange(ec.ECDH(), temp_pk_user)
    digest = hashes.Hash(hashes.SHA256())
    digest.update(shared + nonce)
    k = base64.urlsafe_b64encode(digest.finalize())
    
    f = Fernet(k)
    sym_pt = f.decrypt(sym_ct)
    
    exchange_hash, usedata = sym_pt[:32], sym_pt[32:544]
    
    digest = hashes.Hash(hashes.SHA256())
    digest.update(temp_pk.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
                  + temp_pk_user.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
                  + nonce
                  )
    
    if exchange_hash != digest.finalize():
        print("ERROR: Invalid exchange hash.")
        exit(1) # SHOULD BE CONTINUE OR SOMETHING
    
    usedata = sk_ch.decrypt(
        ciphertext = usedata,
        padding = padding.OAEP(
            mgf = padding.MGF1(algorithm=hashes.SHA256()),
            algorithm = hashes.SHA256(),
            label=None
        )
    )
    
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
    
    send_message(client_sock, confirmation)
    print("Confirmation sent.\nStarting next cycle...")
    time.sleep(5)
    
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

with open("DeviceDB.db", "rb") as h:
    db = h.read()
        
with open("rules.prp", "rb") as r:
    rule = r.read()
    
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(("localhost", PORT))
server_socket.listen(1)

clients = set()
clients_lock = threading.Lock()

token = None
while token == None:
    # WAIT FOR DEVICE TO BE REGISTERED
    try:
        with open("token.prp", "rb") as h:
            token = h.read()
    except FileNotFoundError:
        time.sleep(2)
        continue

time.sleep(1)

while True:
    print("Registered licenses detected.\nListening for connections...")
    
    try:
        # pocakaj na novo povezavo - blokirajoc klic
        client_sock, client_addr = server_socket.accept()
        with clients_lock:
            clients.add(client_sock)

        thread = threading.Thread(target=poll_client, args=(client_sock, client_addr))
        thread.daemon = True
        thread.start()

    except KeyboardInterrupt:
        break

print("[system] closing server socket ...")
server_socket.close()
    