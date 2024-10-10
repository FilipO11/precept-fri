from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
import datetime


def create_ca(common_name: str):
    private_key_ca = rsa.generate_private_key(public_exponent=65537, key_size=4096)

    x509_common_name = x509.NameAttribute(x509.NameOID.COMMON_NAME, common_name)
    subject_name_ca = x509.Name([x509_common_name])

    issuer_ca = x509.Name([x509_common_name])

    builder = x509.CertificateBuilder()
    builder = builder.subject_name(subject_name_ca)
    builder = builder.issuer_name(issuer_ca)
    builder = builder.public_key(private_key_ca.public_key())
    builder = builder.serial_number(x509.random_serial_number())
    now = datetime.datetime.now(datetime.UTC)
    builder = builder.not_valid_before(now)
    builder = builder.not_valid_after(now + datetime.timedelta(days=3650))
    cert_ca = builder.sign(private_key_ca, hashes.SHA256())

    return cert_ca, private_key_ca


def create_csr(common_name: str):
    private_key_csr = rsa.generate_private_key(public_exponent=65537, key_size=4096)

    builder = x509.CertificateSigningRequestBuilder()

    subject_name_csr = x509.Name(
        [x509.NameAttribute(x509.NameOID.COMMON_NAME, common_name)]
    )
    builder = builder.subject_name(subject_name_csr)

    csr = builder.sign(private_key_csr, hashes.SHA256())

    return csr, private_key_csr


def issue_certificate(cert_ca, private_key_ca, csr):
    builder = x509.CertificateBuilder()

    builder = builder.subject_name(csr.subject)
    builder = builder.issuer_name(cert_ca.subject)
    builder = builder.public_key(csr.public_key())
    builder = builder.serial_number(x509.random_serial_number())

    for ext in csr.extensions:
        builder = builder.add_extension(ext.value, critical=False)

    now = datetime.datetime.now(datetime.UTC)
    builder = builder.not_valid_before(now)
    builder = builder.not_valid_after(now + datetime.timedelta(days=365))

    return builder.sign(private_key_ca, hashes.SHA256())


def save_private_key(private_key, filename):
    with open(filename, "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )


def save_certificate(cert, filename):
    with open(filename, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
