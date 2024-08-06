import os, cert, sqlite3
from sqlite3 import Error

def create_connection(path):
    connection = None
    try:
        connection = sqlite3.connect(path)
        print("Connection to SQLite DB successful")
    except Error as e:
        print(f"The error '{e}' occurred")

    return connection

def execute_query(connection, query):
    cursor = connection.cursor()
    try:
        cursor.execute(query)
        connection.commit()
        print("Query executed successfully")
    except Error as e:
        print(f"The error '{e}' occurred")
    
# SQL QUERIES
create_devices_table = """
CREATE TABLE IF NOT EXISTS devices (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  hardware_id BLOB NOT NULL,
  usageok INTEGER,
  lastaudit INTEGER,
  token BLOB
);
"""
# create_licenses_table = """
# CREATE TABLE IF NOT EXISTS licenses (
#   id INTEGER PRIMARY KEY AUTOINCREMENT,
#   dateissued INTEGER,
#   FOREIGN KEY (device_id) REFERENCES devices (id)
#   FOREIGN KEY (token_id) REFERENCES tokens (id)
# );
# """
# create_tokens_table = """
# CREATE TABLE IF NOT EXISTS tokens (
#   id INTEGER PRIMARY KEY AUTOINCREMENT,
#   data BLOB,
#   FOREIGN KEY (device_id) REFERENCES devices (id)
#   FOREIGN KEY (license_id) REFERENCES licenses (id)
# );
# """
try:
    connection = sqlite3.connect("precept.db")
    print("Connection to SQLite DB successful")
except Error as e:
    print(f"The error '{e}' occurred")

cursor = connection.cursor()
try:
    cursor.execute(create_devices_table)
    connection.commit()
    print("Query executed successfully")
except Error as e:
    print(f"The error '{e}' occurred")

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
devices = (
           {"did":did},
)
for i in range(5):
    devices += ({"did":os.urandom(32)},)
try:
    cursor.executemany("INSERT INTO devices(hardware_id) VALUES(:did)", devices)
    connection.commit()
    print("Query executed successfully")
except Error as e:
    print(f"The error '{e}' occurred")
    
cursor.execute("SELECT * FROM devices")
print(cursor.fetchall())