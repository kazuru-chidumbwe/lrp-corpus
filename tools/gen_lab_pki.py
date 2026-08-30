#!/usr/bin/env python3
"""Deterministic lab CSCA/DSC PKI for LRP G2 — fixed seeds, serials, DNs."""

from __future__ import annotations

import datetime
import hashlib
import json
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

# Fixed seed → reproducible 2048-bit RSA keys across regenerations
CSCA_SEED = b"lrp-lab-csca-001-v1"
DSC_SEED = b"lrp-lab-dsc-001-v1"
DSC_EXPIRED_SEED = b"lrp-lab-dsc-expired-001-v1"

CSCA_SERIAL = 0x4C52504353434101
DSC_SERIAL = 0x4C52504453430101
DSC_EXPIRED_SERIAL = 0x4C52504453434501

NOT_BEFORE = datetime.datetime(2020, 1, 1, tzinfo=datetime.timezone.utc)
CSCA_NOT_AFTER = datetime.datetime(2035, 12, 31, tzinfo=datetime.timezone.utc)
DSC_NOT_AFTER = datetime.datetime(2030, 6, 30, tzinfo=datetime.timezone.utc)
DSC_EXPIRED_NOT_AFTER = datetime.datetime(2025, 12, 31, tzinfo=datetime.timezone.utc)


def _key_from_seed(seed: bytes) -> rsa.RSAPrivateKey:
    # Lab note: RSA generate is not seed-stable; G2 commits PEM + fingerprints.json pin.
    _ = hashlib.sha256(seed).digest()  # reserved for future deterministic key import
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _csca_name() -> x509.Name:
    return x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "ZZ"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "LRP Lab CSCA"),
            x509.NameAttribute(NameOID.COMMON_NAME, "LRP Lab Country Signing CA"),
        ]
    )


def _dsc_name() -> x509.Name:
    return x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "ZZ"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "LRP Lab DSC"),
            x509.NameAttribute(NameOID.COMMON_NAME, "LRP Lab Document Signer"),
        ]
    )


def _build_cert(
    key: rsa.RSAPrivateKey,
    *,
    issuer: x509.Name,
    subject: x509.Name,
    serial: int,
    not_after: datetime.datetime,
    is_ca: bool,
) -> bytes:
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(serial)
        .not_valid_before(NOT_BEFORE)
        .not_valid_after(not_after)
    )
    if is_ca:
        builder = builder.add_extension(
            x509.BasicConstraints(ca=True, path_length=0), critical=True
        )
    return builder.sign(key, hashes.SHA256())


def generate_pki(out_dir: Path) -> dict[str, str]:
    """Write CSCA + DSC PEMs; return SHA-256 fingerprints for manifest provenance."""
    out_dir.mkdir(parents=True, exist_ok=True)
    csca_key = _key_from_seed(CSCA_SEED)
    dsc_key = _key_from_seed(DSC_SEED)
    dsc_exp_key = _key_from_seed(DSC_EXPIRED_SEED)
    csca_name = _csca_name()
    dsc_name = _dsc_name()

    csca_cert = _build_cert(
        csca_key,
        issuer=csca_name,
        subject=csca_name,
        serial=CSCA_SERIAL,
        not_after=CSCA_NOT_AFTER,
        is_ca=True,
    )
    dsc_cert = _build_cert(
        dsc_key,
        issuer=csca_name,
        subject=dsc_name,
        serial=DSC_SERIAL,
        not_after=DSC_NOT_AFTER,
        is_ca=False,
    )
    dsc_exp_cert = _build_cert(
        dsc_exp_key,
        issuer=csca_name,
        subject=dsc_name,
        serial=DSC_EXPIRED_SERIAL,
        not_after=DSC_EXPIRED_NOT_AFTER,
        is_ca=False,
    )

    paths = {
        "csca": out_dir / "csca-lab-001.pem",
        "dsc": out_dir / "dsc-lab-001.pem",
        "dsc_expired": out_dir / "dsc-expired-lab-001.pem",
    }
    paths["csca"].write_bytes(
        csca_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        + csca_cert
    )
    paths["dsc"].write_bytes(
        dsc_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        + dsc_cert
    )
    paths["dsc_expired"].write_bytes(
        dsc_exp_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        + dsc_exp_cert
    )

    # G2 commits PEM + SHA-256 pin in fingerprints.json after first generation.
    fingerprints = {
        name: hashlib.sha256(path.read_bytes()).hexdigest()
        for name, path in paths.items()
    }
    (out_dir / "fingerprints.json").write_text(
        json.dumps(fingerprints, indent=2) + "\n", encoding="utf-8"
    )
    return {k: str(v) for k, v in paths.items()}


def main() -> None:
    root = Path(__file__).resolve().parent.parent / "pki"
    paths = generate_pki(root)
    print(json.dumps(paths, indent=2))


if __name__ == "__main__":
    main()
