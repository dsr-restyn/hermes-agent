"""Local CA for HTTPS MITM.

Generates a self-signed CA keypair on first run and stores it at:
  ~/.hermes/state/cred-proxy-ca/ca.key  (chmod 600)
  ~/.hermes/state/cred-proxy-ca/ca.crt

Per-hostname certs are issued on demand and cached in memory.
"""

import ipaddress
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

_DEFAULT_CA_DIR = Path.home() / ".hermes" / "state" / "cred-proxy-ca"


def _generate_ca_pair():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "Hermes Cred Proxy CA"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Hermes Agent"),
    ])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    return key, cert


class LocalCA:
    def __init__(self, ca_dir: Path = _DEFAULT_CA_DIR):
        self._ca_dir = Path(ca_dir)
        self._cert_cache: dict[str, tuple[bytes, bytes]] = {}
        self._ensure_ca()

    def _ensure_ca(self) -> None:
        self._ca_dir.mkdir(parents=True, exist_ok=True)
        key_file = self._ca_dir / "ca.key"
        cert_file = self._ca_dir / "ca.crt"

        if not key_file.exists() or not cert_file.exists():
            key, cert = _generate_ca_pair()
            key_pem = key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            )
            cert_pem = cert.public_bytes(serialization.Encoding.PEM)
            key_file.write_bytes(key_pem)
            key_file.chmod(0o600)
            cert_file.write_bytes(cert_pem)

        self._ca_key = serialization.load_pem_private_key(
            key_file.read_bytes(), password=None
        )
        self._ca_cert = x509.load_pem_x509_certificate(
            (self._ca_dir / "ca.crt").read_bytes()
        )

    def get_ca_cert_pem(self) -> bytes:
        """Return the CA certificate PEM bytes (safe to distribute to clients)."""
        return (self._ca_dir / "ca.crt").read_bytes()

    def issue_cert(self, hostname: str) -> tuple[bytes, bytes]:
        """Issue a cert for *hostname* signed by this CA.

        Returns (cert_pem, key_pem).  Results are cached in memory.
        """
        if hostname in self._cert_cache:
            return self._cert_cache[hostname]

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)])

        try:
            ip = ipaddress.ip_address(hostname)
            san = x509.SubjectAlternativeName([x509.IPAddress(ip)])
        except ValueError:
            san = x509.SubjectAlternativeName([x509.DNSName(hostname)])

        now = datetime.now(timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(self._ca_cert.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + timedelta(days=365))
            .add_extension(san, critical=False)
            .sign(self._ca_key, hashes.SHA256())
        )

        cert_pem = cert.public_bytes(serialization.Encoding.PEM)
        key_pem = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )

        self._cert_cache[hostname] = (cert_pem, key_pem)
        return cert_pem, key_pem
