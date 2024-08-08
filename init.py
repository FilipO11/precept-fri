import os, cert, pickle

# INITIALIZE SERIAL NUMBER RECORD
sn = 0
with open("sn.prp", "wb") as r:
    r.write(sn.to_bytes(8, "big"))

# CREATE RULES FILE
with open("rules.prp", "wb") as h: 
    h.write(os.urandom(8))

# PREPARE DIRECTORIES
if not os.path.exists("pki"): os.mkdir("pki")
if not os.path.exists("ids"): os.mkdir("ids")
if not os.path.exists("comms"): os.mkdir("comms")

# CREATE CERTIFICATES
cert_ca, sk_ca = cert.create_ca("PrecePt CA")
cert.save_certificate(cert_ca, "pki/cert_ca.pem")
cert.save_private_key(sk_ca, "pki/sk_ca.pem")

csr_user, sk_user = cert.create_csr("User")
cert.save_private_key(sk_user, "pki/sk_user.pem")
cert_user = cert.issue_certificate(cert_ca, sk_ca, csr_user)
cert.save_certificate(cert_user, "pki/cert_user.pem")

csr_ls, sk_ls = cert.create_csr("License Server")
cert.save_private_key(sk_ls, "pki/sk_ls.pem")
cert_ls = cert.issue_certificate(cert_ca, sk_ca, csr_ls)
cert.save_certificate(cert_ls, "pki/cert_ls.pem")

csr_ch, sk_ch = cert.create_csr("Clearing House")
cert.save_private_key(sk_ch, "pki/sk_ch.pem")
cert_ch = cert.issue_certificate(cert_ca, sk_ca, csr_ch)
cert.save_certificate(cert_ch, "pki/cert_ch.pem")

# GENERATE IDS
with open("ids/Content_ID.id", "wb") as h: 
    h.write(os.urandom(32))
with open("ids/LS_ID.id", "wb") as h: 
    h.write(os.urandom(32))
with open("ids/CH_ID.id", "wb") as h: 
    h.write(os.urandom(32))
with open("ids/D_ID.id", "wb") as h:
    did = os.urandom(32)
    h.write(did)

# GENERATE DEVICE DB
db = {}
db[did] = b''
for i in range(100):
    db[os.urandom(32)] = b''
with open("DeviceDB.db", "wb") as dbfile:
    pickle.dump(db, dbfile)
