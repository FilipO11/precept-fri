# IMPORTS
import datetime, os, base64, pickle, falcon
from wsgiref.simple_server import make_server
from cryptography import x509
from cryptography.fernet import Fernet
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding

class LicenseIssuer:
    def __init__(self):
        self.clients = dict()
        
    def on_post(self, req, resp):
        msg = req.get_media()
        msgtype = msg.get("type")
        msgbody = bytes.fromhex(msg.get("body"))
        
        if msgtype == "request":
            rm, params = self.issue_license(msgbody)
            self.clients[req.remote_addr] = params
            resp.media = {"response" : rm}
            resp.status = falcon.HTTP_200
        
        elif msgtype == "confirmation":
            params = self.clients[req.remote_addr]
            rm = self.process_confirmation(msgbody, params)
    
    def process_confirmation(self, confirmation, params):
        k, temp_pk, temp_pk_user, did, license = params["k"], params["temp_pk"], params["temp_pk_user"], params["did"], params["license"]
        with open("sn.prp", "rb") as r:
            sn = int.from_bytes(r.read())
        with open("DeviceDB.db", "rb") as dbfile:
            db = pickle.load(dbfile)
        print("Confirmation received.")
        
        f = Fernet(k)
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
        with open("DeviceDB.db", "wb") as dbfile:
            pickle.dump(db, dbfile)
        
        sn += 1
        with open("sn.prp", "wb") as h:
            h.write(sn.to_bytes(8, "big"))
            
        print("Finished.\n")
        return True

    def issue_license(self, msg):
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
        
        license = sn.to_bytes(8, "big") + kid + date + rule + other_data
        print("LICENSE BREAKDOWN\n\tsn: %i\n\tkid: %i\n\tdate: %i\n\trule: %i\n\tother data: %i\n\tlicense data: %i" % 
            (len(sn.to_bytes(8, "big")), 
            len(kid), 
            len(date), 
            len(rule), 
            len(other_data), 
            len(license))
        )
        sig_lic = sk_ls.sign(
            license, 
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        license += sig_lic
        print("\tsig: %i\nlicense full (w/ sig): %i\n" % (len(sig_lic), len(license)))
        
        # asym encrpyt license via hybrid cipher
        lic_enc_k = Fernet.generate_key()
        lic_f = Fernet(lic_enc_k)
        license_enc = lic_f.encrypt(license)
        
        lic_enc_k = cert_user.public_key().encrypt(
            plaintext = lic_enc_k,
            padding = padding.OAEP(
                mgf = padding.MGF1(algorithm=hashes.SHA256()),
                algorithm = hashes.SHA256(),
                label=None
            )
        )
        
        f = Fernet(k)
        pt = exchange_hash + license_enc + lic_enc_k + contentid
        
        sig_fer = sk_ls.sign(
            pt, 
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        pt += sig_fer + cert_ls_pem
        
        print("FERNET BREAKDOWN\n\texchange hash: %i\n\tlicense (enc w/ lic_k): %i\n\tlicense key(enc w/ pk_user): %i\n\tcontent id: %i\n\tfer signature: %i\n\tcertificate: %i\nfernet full: %i\n" % 
            (len(exchange_hash),
            len(license_enc),
            len(lic_enc_k),
            len(contentid),
            len(sig_fer),
            len(cert_ls_pem),
            len(pt))
        )
                
        response = temp_pk.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo) + nonce + f.encrypt(pt)
        params = {
            "k": k,
            "temp_pk": temp_pk,
            "temp_pk_user": temp_pk_user,
            "did": did,
            "license": license
            }
        
        print("Issued license.\nWaiting for confirmation...")
        return response.hex(), params

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

app = falcon.App()
issuer = LicenseIssuer()
app.add_route("/acqlic", issuer)

# LISTEN FOR LICENSE REQUESTS
if __name__ == '__main__':
    with make_server('', 50000, app) as httpd:
        print('Serving on port 50000...')

        # Serve until process is killed
        httpd.serve_forever()
