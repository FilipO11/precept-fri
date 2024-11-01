# IMPORTS
import datetime, time, os, base64, pickle, falcon, falcon.asgi, uvicorn
from cryptography import x509
from cryptography.fernet import Fernet
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization, constant_time
from cryptography.hazmat.primitives.asymmetric import ec, padding


def xor_bytes(s1, s2):
    res = []
    for i in range(min(len(s1), len(s2))):
        res.append(s1[i] ^ s2[i])

    return bytes(res)


class LicenseIssuer:
    def __init__(self):
        self.clients = dict()  # Dictionary for storing license acquisition parameters

    async def on_post(self, req, resp):
        msg = await req.get_media()
        msgtype = msg.get("type")
        msgbody = base64.urlsafe_b64decode(msg.get("body"))

        if msgtype == "request":
            rm, params = self.issue_license(msgbody)
            self.clients[req.remote_addr] = (
                params  # Save session parameters for confirmation processing
            )
            resp.media = {"response": rm}
            if params != {}:
                resp.status = falcon.HTTP_200
            else:
                resp.status = falcon.HTTP_403

        elif msgtype == "confirmation":
            params = self.clients[req.remote_addr]
            rm = self.process_confirmation(msgbody, params)
            resp.media = {"response": rm}
            if rm:
                resp.status = falcon.HTTP_200
            else:
                resp.status = falcon.HTTP_400

    def issue_license(self, msg):
        with open("DeviceDB.db", "rb") as dbfile:
            db = pickle.load(dbfile)

        with open("rules.prp", "rb") as r:
            rule = r.read()
        
        with open("otherdata.prp", "rb") as o:
            other_data = o.read()

        # 1. Unpack message: ContentID, TID (encrypted)
        contentid, tid_enc = msg[:32], msg[32:]

        # 2. Decrypt TID using LS secret key
        tid = sk_ls.decrypt(
            ciphertext=tid_enc,
            padding=padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

        # 3. Deserialize user's temporary public key and extract DeviceID via XOR (DID = TU ^ TU ^ DID)
        temp_pk_user = serialization.load_pem_public_key(tid[:174])
        did = xor_bytes(tid[:174], tid[174:])
        did = did[:32]

        # 4. Check if DeviceID is in the device database
        if not (did in db):
            print("ERROR: Device not registered!")
            return base64.urlsafe_b64encode("NOTREGISTERED").decode("ascii"), {}

        # 5. Generate exchange keys and nonce
        temp_sk = ec.generate_private_key(ec.SECP256K1())
        temp_pk = temp_sk.public_key()
        nonce = os.urandom(32)

        # 6. Derive session key
        shared = temp_sk.exchange(ec.ECDH(), temp_pk_user)
        digest = hashes.Hash(hashes.SHA256())
        digest.update(shared + nonce)
        k = base64.urlsafe_b64encode(digest.finalize())

        # 7. Calculate exchange hash H(r || T_LS || T_U)
        digest = hashes.Hash(hashes.SHA256())
        digest.update(
            nonce
            + temp_pk.public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            + temp_pk_user.public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
        exchange_hash = digest.finalize()

        # 8. Calculate KID H(DeviceID || LicenseServerID)
        digest = hashes.Hash(hashes.SHA256())
        digest.update(did + lsid)
        kid = digest.finalize()

        # 9. Record date
        date = datetime.date.today().isoformat().encode("utf-8")

        # 10. Load other data

        # 11. Assemble license
        license = os.urandom(8) + kid + date + rule + other_data
        sig_lic = sk_ls.sign(
            license,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256(),
        )
        license += sig_lic

        # 12. Asymetrically encrypt license via hybrid cipher
        lic_enc_k = Fernet.generate_key()
        lic_f = Fernet(lic_enc_k)
        license_enc = lic_f.encrypt(license)

        lic_enc_k = cert_user.public_key().encrypt(
            plaintext=lic_enc_k,
            padding=padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

        # 13. Initialize Fernet cipher and assemble response plaintext
        f = Fernet(k)
        pt = exchange_hash + license_enc + lic_enc_k + contentid

        # 14. Sign part of the (to be) symetrically encrypted plaintext
        sig_fer = sk_ls.sign(
            pt,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256(),
        )
        pt += sig_fer + cert_ls_pem  # Add signature and LS certificate to the plaintext

        # 15. Assemble response payload
        response = (
            temp_pk.public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            + nonce
            + f.encrypt(pt)
        )
        params = {
            "k": k,
            "did": did,
        }

        print("Issued license.\nWaiting for confirmation...")
        return base64.urlsafe_b64encode(response).decode("ascii"), params

    def process_confirmation(self, confirmation, params):
        k, did = (
            params["k"],
            params["did"],
        )
        with open("DeviceDB.db", "rb") as dbfile:
            db = pickle.load(dbfile)
        print("Confirmation received.")

        # 1. Decrypt symetric ciphertext
        f = Fernet(k)
        pt = f.decrypt(confirmation, None)
        confirmation_hash, token, conf_sig = pt[:32], pt[32:64], pt[64:]

        # 2. Check confirmation signature
        try:
            print("Checking confirmation...")
            cert_user.public_key().verify(
                conf_sig,
                confirmation_hash + token,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )
            print("Confirmation verified.\nFinalizing...")
        except InvalidSignature:
            print("ERROR: Invalid confirmation signature.")
            return False

        # 3. Save token to device database
        db[did] = token
        with open("DeviceDB.db", "wb") as dbfile:
            pickle.dump(db, dbfile)

        print("Finished.\n")
        return True


class UsageTracker:
    async def on_websocket(self, req, ws):
        await ws.accept()

        did = await ws.receive_data()
        did = sk_ch.decrypt(
            ciphertext=did,
            padding=padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

        # 1. Search for token
        with open("DeviceDB.db", "rb") as dbfile:
            db = pickle.load(dbfile)
            token = db[did]
            if token is None:
                print("ERROR: Device token not found.\nClosing connection.")
                await ws.send_data(bytes(4))
                await ws.close()

        while True:
            # 2. Generate exchange keys
            temp_sk = ec.generate_private_key(ec.SECP256K1())
            temp_pk = temp_sk.public_key()

            # 3. Assemble request plaintext
            request = (
                token
                + chid
                + temp_pk.public_bytes(
                    serialization.Encoding.PEM,
                    serialization.PublicFormat.SubjectPublicKeyInfo,
                )
                + cert_ch_pem
            )

            # 4. Encrypt request plaintext via hybrid scheme
            request_enc_k = Fernet.generate_key()
            req_f = Fernet(request_enc_k)
            request_enc = req_f.encrypt(request)

            request_enc_k = cert_user.public_key().encrypt(
                plaintext=request_enc_k,
                padding=padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )

            await ws.send_data(request_enc_k + request_enc)
            print("Usage data request sent.\nWaiting for data...")

            response = await ws.receive_data()
            print("Data received.\nProcessing response...")

            # 5. Unpack response
            temp_pk_user, nonce, sym_ct = (
                response[:174],
                response[174:206],
                response[206:],
            )
            temp_pk_user = serialization.load_pem_public_key(temp_pk_user)

            # 6. Derive session key
            shared = temp_sk.exchange(ec.ECDH(), temp_pk_user)
            digest = hashes.Hash(hashes.SHA256())
            digest.update(shared + nonce)
            k = base64.urlsafe_b64encode(digest.finalize())

            # 7. Decrypt the symetric ciphertext
            f = Fernet(k)
            sym_pt = f.decrypt(sym_ct)

            # 8. Unpack the symetric plaintext
            exchange_hash, usedata_enc_k, datasig, token_user, usedata_enc = (
                sym_pt[:32],
                sym_pt[32:544],
                sym_pt[544:1056],
                sym_pt[1056:1088],
                sym_pt[1088:],
            )

            # 9. Calculate exchange hash and verify it
            digest = hashes.Hash(hashes.SHA256())
            digest.update(
                temp_pk.public_bytes(
                    serialization.Encoding.PEM,
                    serialization.PublicFormat.SubjectPublicKeyInfo,
                )
                + temp_pk_user.public_bytes(
                    serialization.Encoding.PEM,
                    serialization.PublicFormat.SubjectPublicKeyInfo,
                )
                + nonce
            )

            if not constant_time.bytes_eq(exchange_hash, digest.finalize()):
                print("ERROR: Invalid exchange hash.")
                await ws.send("INVALID EXCHANGE HASH")

            # 10. Check response signature
            try:
                print("Checking response signature...")
                cert_user.public_key().verify(
                    datasig,
                    exchange_hash + usedata_enc,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH,
                    ),
                    hashes.SHA256(),
                )
            except InvalidSignature:
                print("ERROR: Invalid response signature.")
                exit(1)

            # 11. Asymetrically decrypt hybrid cipher key, then decrypt usage data
            usedata_k = sk_ch.decrypt(
                ciphertext=usedata_enc_k,
                padding=padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )

            ud_f = Fernet(usedata_k)
            usedata = ud_f.decrypt(usedata_enc)
            print("Response verified.\nPreparing confirmation...")

            # 12. Calculate and encrypt confirmation signature
            digest = hashes.Hash(hashes.SHA256())
            digest.update(
                temp_pk.public_bytes(
                    serialization.Encoding.PEM,
                    serialization.PublicFormat.SubjectPublicKeyInfo,
                )
                + temp_pk_user.public_bytes(
                    serialization.Encoding.PEM,
                    serialization.PublicFormat.SubjectPublicKeyInfo,
                )
                + k
                + usedata
            )
            confirmation = digest.finalize()
            confirmation += sk_ch.sign(
                confirmation,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )

            confirmation = f.encrypt(confirmation)

            await ws.send_data(confirmation)
            print("Confirmation sent.\nStarting next cycle...")

            time.sleep(5)


# LOAD FROM FILES
try:
    with open("pki/sk_ls.pem", "rb") as h:
        pem_data = h.read()
    sk_ls = serialization.load_pem_private_key(pem_data, None)

    with open("pki/sk_ch.pem", "rb") as h:
        pem_data = h.read()
    sk_ch = serialization.load_pem_private_key(pem_data, None)

    with open("pki/cert_user.pem", "rb") as c:
        pem_data = c.read()
    cert_user = x509.load_pem_x509_certificate(pem_data)

    with open("pki/cert_ls.pem", "rb") as c:
        cert_ls_pem = c.read()

    with open("pki/cert_ch.pem", "rb") as c:
        cert_ch_pem = c.read()

    with open("ids/LS_ID.id", "rb") as c:
        lsid = c.read()

    with open("ids/CH_ID.id", "rb") as c:
        chid = c.read()

    with open("rules.prp", "rb") as r:
        rule = r.read()
except FileNotFoundError as e:
    print("File system error. Could not load data from " + e.filename)

app = falcon.asgi.App()
issuer = LicenseIssuer()
checker = UsageTracker()
app.add_route("/acqlic", issuer)
app.add_route("/tracking", checker)

# LISTEN FOR LICENSE REQUESTS
if __name__ == "__main__":
    uvicorn.run("LicenseServer:app", host="localhost", port=8000, reload=True)
