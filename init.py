import base64, os, cert, pickle
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes

# PREPARE DIRECTORIES
if not os.path.exists("server/pki"):
    os.mkdir("server/pki")
if not os.path.exists("server/ids"):
    os.mkdir("server/ids")
if not os.path.exists("client/pki"):
    os.mkdir("client/pki")
if not os.path.exists("client/ids"):
    os.mkdir("client/ids")
if not os.path.exists("ca"):
    os.mkdir("ca")

# CREATE CERTIFICATES
cert_ca, sk_ca = cert.create_ca("PrecePt CA")
cert.save_certificate(cert_ca, "ca/cert_ca.pem")
cert.save_certificate(cert_ca, "server/pki/cert_ca.pem")
cert.save_certificate(cert_ca, "client/pki/cert_ca.pem")
cert.save_private_key(sk_ca, "ca/sk_ca.pem")

csr_user, sk_user = cert.create_csr("User")
cert.save_private_key(sk_user, "client/pki/sk_user.pem")
cert_user = cert.issue_certificate(cert_ca, sk_ca, csr_user)
cert.save_certificate(cert_user, "client/pki/cert_user.pem")
cert.save_certificate(cert_user, "server/pki/cert_user.pem")

csr_ls, sk_ls = cert.create_csr("License Server")
cert.save_private_key(sk_ls, "server/pki/sk_ls.pem")
cert_ls = cert.issue_certificate(cert_ca, sk_ca, csr_ls)
cert.save_certificate(cert_ls, "server/pki/cert_ls.pem")
cert.save_certificate(cert_ls, "client/pki/cert_ls.pem")

csr_ch, sk_ch = cert.create_csr("Clearing House")
cert.save_private_key(sk_ch, "server/pki/sk_ch.pem")
cert_ch = cert.issue_certificate(cert_ca, sk_ca, csr_ch)
cert.save_certificate(cert_ch, "server/pki/cert_ch.pem")
cert.save_certificate(cert_ch, "client/pki/cert_ch.pem")

# GENERATE IDS
with open("server/ids/LS_ID.id", "wb") as h:
    h.write(os.urandom(32))
with open("server/ids/CH_ID.id", "wb") as h:
    h.write(os.urandom(32))
with open("client/ids/Content_ID.id", "wb") as h:
    cid = os.urandom(32)
    h.write(cid)
with open("client/ids/D_ID.id", "wb") as h:
    did = os.urandom(32)
    h.write(did)

# CREATE RULES FILE
with open("server/rules.prp", "wb") as h:
    rules = os.urandom(8)
    h.write(rules)

with open("server/otherdata.prp", "wb") as h:
    other_data = os.urandom(32)
    h.write(other_data)

# ENCRYPT CONTENT
digest = hashes.Hash(hashes.SHA256())
digest.update(rules + other_data + cid)
k = base64.urlsafe_b64encode(digest.finalize())
f = Fernet(k)

with open("image.jpg", "rb") as imgfile:
    img = imgfile.read()
img = f.encrypt(img)
with open("client/content.prp", "wb") as h:
    h.write(img)

# GENERATE DEVICE DB
db = {}
db[did] = b""
for i in range(100):
    db[os.urandom(32)] = b""
with open("server/DeviceDB.db", "wb") as dbfile:
    pickle.dump(db, dbfile)
