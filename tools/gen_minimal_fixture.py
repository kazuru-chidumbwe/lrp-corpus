#!/usr/bin/env python3
"""Build minimal LRP dry-run blob set with SOD hashes over complete EF bytes."""

from __future__ import annotations

import datetime
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from lds_hash import (
    HASH_OID_TO_NAME,
    build_lds_security_object,
    build_signed_data,
    hash_ef_bytes,
    retag_as_ef_sod,
)

ROOT = Path(__file__).resolve().parent
OUT = ROOT / "testdata" / "minimal"

# ICAO Doc 9303 Part 10 Appendix A — DG1/DG2 worked examples (gmrtd sample_document.go)
DG1_HEX = (
    "614B5F1F48493C55544F4552494B53534F4E3C3C414E4E413C4D415249413C3C3C3C3C3C3C3C3C3C3C"
    "4432333134353839303755544F3734303831323246313230343135393C3C3C3C3C3C3C36"
)
# Minimal EF.DG2 shell (tag 0x75) — complete EF bytes hashed per Doc 9303-10
DG2_HEX = "750400000000"


def _self_signed_cert() -> tuple[rsa.RSAPrivateKey, bytes]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "ZZ"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "LRP verify-dry-run fixture"),
            x509.NameAttribute(NameOID.COMMON_NAME, "LRP minimal self-signed DSC"),
        ]
    )
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=3650))
        .sign(key, hashes.SHA256())
    )
    return key, cert.public_bytes(serialization.Encoding.DER)


def main() -> None:
    dg1 = bytes.fromhex(DG1_HEX)
    dg2 = bytes.fromhex(DG2_HEX)
    hash_oid = "2.16.840.1.101.3.4.2.1"  # SHA-256
    hash_name = HASH_OID_TO_NAME[hash_oid]

    dg_hashes = [
        (1, hash_ef_bytes(hash_oid, dg1)),
        (2, hash_ef_bytes(hash_oid, dg2)),
    ]
    lds_so = build_lds_security_object(hash_oid, dg_hashes)
    key, cert_der = _self_signed_cert()
    sod_ef = retag_as_ef_sod(build_signed_data(key, cert_der, lds_so, hash_name=hash_name))

    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "dg1.bin").write_bytes(dg1)
    (OUT / "dg2.bin").write_bytes(dg2)
    (OUT / "sod.bin").write_bytes(sod_ef)
    (OUT / "manifest.json").write_text(
        (
            '{\n'
            '  "profile_id": "lrp-fixture-minimal-001",\n'
            '  "files": {"EF.DG1": "dg1.bin", "EF.DG2": "dg2.bin", "EF.SOD": "sod.bin"}\n'
            "}\n"
        ),
        encoding="utf-8",
    )
    print(f"Wrote fixture to {OUT}")
    print(f"  DG1 {len(dg1)} bytes  DG2 {len(dg2)} bytes  SOD {len(sod_ef)} bytes")


if __name__ == "__main__":
    main()
