import os, cert, pickle

# PREPARE DIRECTORIES
if not os.path.exists("server/pki"): os.mkdir("server/pki")
if not os.path.exists("server/ids"): os.mkdir("server/ids")
if not os.path.exists("client/pki"): os.mkdir("client/pki")
if not os.path.exists("client/ids"): os.mkdir("client/ids")
if not os.path.exists("ca"): os.mkdir("ca")

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
    h.write(os.urandom(32))
with open("client/ids/D_ID.id", "wb") as h:
    did = os.urandom(32)
    h.write(did)

# INITIALIZE SERIAL NUMBER RECORD
sn = 0
with open("server/sn.prp", "wb") as r:
    r.write(sn.to_bytes(8, "big"))

# CREATE RULES FILE
with open("server/rules.prp", "wb") as h: 
    h.write(os.urandom(8))

# GENERATE DEVICE DB
db = {}
db[did] = b''
for i in range(100):
    db[os.urandom(32)] = b''
with open("server/DeviceDB.db", "wb") as dbfile:
    pickle.dump(db, dbfile)
