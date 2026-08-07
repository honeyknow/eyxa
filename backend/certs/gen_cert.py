"""
Generates a self-signed TLS certificate for local Eyxa backend development.
Outputs key.pem and cert.pem in the same directory as this script.
Uses the `cryptography` package (already installed as bcrypt dependency).
Source: https://cryptography.io/en/latest/x509/reference/
HARDENING: Replace with a CA-signed certificate before Phase 9 validation.
"""
import datetime, pathlib
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

HERE = pathlib.Path(__file__).parent
key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
subject = issuer = x509.Name([
    x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Eyxa-Dev"),
    x509.NameAttribute(NameOID.COUNTRY_NAME, "IN"),
])
cert = (
    x509.CertificateBuilder()
    .subject_name(subject)
    .issuer_name(issuer)
    .public_key(key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
    .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365))
    .add_extension(x509.SubjectAlternativeName([
        x509.DNSName("localhost"),
        x509.IPAddress(__import__("ipaddress").ip_address("127.0.0.1")),
    ]), critical=False)
    .sign(key, hashes.SHA256())
)
(HERE / "key.pem").write_bytes(key.private_bytes(
    serialization.Encoding.PEM,
    serialization.PrivateFormat.TraditionalOpenSSL,
    serialization.NoEncryption(),
))
(HERE / "cert.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
print(f"[OK] key.pem and cert.pem written to {HERE}")
