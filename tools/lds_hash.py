"""ICAO Doc 9303-10 LDS hash helpers — complete EF bytes per dataGroupHashValue."""

from __future__ import annotations

import hashlib
from typing import Iterable

from asn1crypto import algos, cms, core, x509 as asn1_x509

ID_MRTD_LDS_SECURITY_OBJECT = "2.23.136.1.1.1"

HASH_OID_TO_NAME: dict[str, str] = {
    "1.3.14.3.2.26": "sha1",
    "2.16.840.1.101.3.4.2.1": "sha256",
    "2.16.840.1.101.3.4.2.2": "sha384",
    "2.16.840.1.101.3.4.2.3": "sha512",
}

# Hash-listed DGs per Doc 9303-10 Table 4 class sampling (DG13 excluded — not in corpus Table 4).
# DG3 is included: SOD may list a DG3 hash even when the EF is unreadable without EAC.
HASHABLE_DG_NUMBERS = (1, 2, 3, 7, 11, 12, 14, 15, 16)

EF_KEY_TO_DG: dict[str, int] = {
    "EF.DG1": 1,
    "EF.DG2": 2,
    "EF.DG3": 3,  # hash-listed; often unreadable without EAC — still in SOD hash set
    "EF.DG7": 7,
    "EF.DG11": 11,
    "EF.DG12": 12,
    "EF.DG14": 14,
    "EF.DG15": 15,
    "EF.DG16": 16,
}


def der_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    parts: list[int] = []
    while n:
        parts.insert(0, n & 0xFF)
        n >>= 8
    return bytes([0x80 | len(parts)]) + bytes(parts)


def unwrap_ef_sod(sod_ef: bytes) -> bytes:
    """Strip EF.SOD APPLICATION 23 (0x77) wrapper when present."""
    if not sod_ef:
        raise ValueError("empty EF.SOD")
    if sod_ef[0] != 0x77:
        return sod_ef
    offset = 1
    length_byte = sod_ef[offset]
    offset += 1
    if length_byte & 0x80:
        num_len_bytes = length_byte & 0x7F
        length = int.from_bytes(sod_ef[offset : offset + num_len_bytes], "big")
        offset += num_len_bytes
    else:
        length = length_byte
    inner = sod_ef[offset : offset + length]
    if len(inner) != length:
        raise ValueError("truncated EF.SOD TLV")
    return inner


def parse_lds_security_object(der: bytes) -> tuple[int, str, list[tuple[int, bytes]]]:
    seq = core.Sequence.load(der)
    version = int(seq[0].native)
    hash_alg = algos.DigestAlgorithm.load(seq[1].dump())
    hash_oid = hash_alg["algorithm"].dotted
    dg_hashes: list[tuple[int, bytes]] = []
    dg_values = seq[2]
    for idx in range(len(dg_values)):
        entry = core.Sequence.load(dg_values[idx].dump())
        dg_num = int(entry[0].native)
        dg_hash = entry[1].native
        if not isinstance(dg_hash, (bytes, bytearray)):
            raise ValueError(f"unexpected DG hash type for DG{dg_num}")
        dg_hashes.append((dg_num, bytes(dg_hash)))
    return version, hash_oid, dg_hashes


def extract_lds_from_ef_sod(sod_ef: bytes) -> tuple[str, list[tuple[int, bytes]]]:
    content_info = cms.ContentInfo.load(unwrap_ef_sod(sod_ef))
    if content_info["content_type"].native != "signed_data":
        raise ValueError(f"unexpected CMS content type: {content_info['content_type'].native}")
    signed = content_info["content"]
    econtent = signed["encap_content_info"]["content"].native
    if not isinstance(econtent, (bytes, bytearray)):
        raise ValueError("LDS Security Object eContent is not OCTET STRING bytes")
    _version, hash_oid, dg_hashes = parse_lds_security_object(bytes(econtent))
    return hash_oid, dg_hashes


def hash_name_for_oid(oid: str) -> str:
    name = HASH_OID_TO_NAME.get(oid)
    if not name:
        raise ValueError(f"unsupported hash OID in SOD: {oid}")
    return name


def hash_ef_bytes(hash_oid: str, ef_bytes: bytes) -> bytes:
    name = hash_name_for_oid(hash_oid)
    return hashlib.new(name, ef_bytes).digest()


def dg2_inner_after_75(ef_dg2: bytes) -> bytes:
    """Legacy wrong boundary — hash payload after 0x75 tag+length (NOT Doc 9303-10)."""
    if ef_dg2[0] != 0x75:
        raise ValueError("EF.DG2 does not start with tag 0x75")
    offset = 1
    length_byte = ef_dg2[offset]
    offset += 1
    if length_byte & 0x80:
        num_len_bytes = length_byte & 0x7F
        length = int.from_bytes(ef_dg2[offset : offset + num_len_bytes], "big")
        offset += num_len_bytes
    else:
        length = length_byte
    return ef_dg2[offset : offset + length]


def build_lds_security_object(
    hash_oid: str,
    dg_hashes: Iterable[tuple[int, bytes]],
    *,
    version: int = 0,
) -> bytes:
    hash_alg = algos.DigestAlgorithm({"algorithm": hash_name_for_oid(hash_oid)})
    entries: list[bytes] = []
    for dg_num, dg_hash in dg_hashes:
        body = core.Integer(dg_num).dump() + core.OctetString(dg_hash).dump()
        entries.append(b"\x30" + der_len(len(body)) + body)
    dg_values = b"".join(entries)
    dg_values_seq = b"\x30" + der_len(len(dg_values)) + dg_values
    body = core.Integer(version).dump() + hash_alg.dump() + dg_values_seq
    return b"\x30" + der_len(len(body)) + body


def retag_as_ef_sod(content_info_der: bytes) -> bytes:
    if content_info_der[0] != 0x30:
        raise ValueError("expected CMS ContentInfo SEQUENCE")
    return b"\x77" + der_len(len(content_info_der)) + content_info_der


def build_signed_data(
    key,
    cert_der: bytes,
    econtent: bytes,
    *,
    hash_name: str,
    signature_scheme: str = "pkcs1v15",
) -> bytes:
    """Build CMS SignedData for lab fixtures.

    signature_scheme:
      - ``pkcs1v15`` — RSA PKCS#1 v1.5 (default; SHA-1/256/384/512)
      - ``rsassa_pss`` — RSASSA-PSS with MGF1 (SHA-384/512 reader-arm profiles)
    """
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding

    hash_algs = {
        "sha1": hashes.SHA1(),
        "sha256": hashes.SHA256(),
        "sha384": hashes.SHA384(),
        "sha512": hashes.SHA512(),
    }
    if hash_name not in hash_algs:
        raise ValueError(f"unsupported hash for CMS signing: {hash_name}")
    if signature_scheme not in ("pkcs1v15", "rsassa_pss"):
        raise ValueError(f"unsupported signature_scheme: {signature_scheme}")

    digest = hashlib.new(hash_name, econtent).digest()
    signed_attrs = cms.CMSAttributes(
        [
            cms.CMSAttribute(
                {
                    "type": "content_type",
                    "values": [cms.ContentType(ID_MRTD_LDS_SECURITY_OBJECT)],
                }
            ),
            cms.CMSAttribute(
                {
                    "type": "message_digest",
                    "values": [core.OctetString(digest)],
                }
            ),
        ]
    )
    signed_attrs_der = signed_attrs.dump()
    hash_alg = hash_algs[hash_name]
    if signature_scheme == "pkcs1v15":
        signature = key.sign(signed_attrs_der, padding.PKCS1v15(), hash_alg)
        sig_alg_oid = f"{hash_name}_rsa"
    else:
        signature = key.sign(
            signed_attrs_der,
            padding.PSS(mgf=padding.MGF1(hash_alg), salt_length=padding.PSS.MAX_LENGTH),
            hash_alg,
        )
        sig_alg_oid = f"{hash_name}_rsa_pss"

    cert = asn1_x509.Certificate.load(cert_der)
    signer_info = cms.SignerInfo(
        {
            "version": "v1",
            "sid": cms.SignerIdentifier(
                {
                    "issuer_and_serial_number": cms.IssuerAndSerialNumber(
                        {
                            "issuer": cert["tbs_certificate"]["issuer"],
                            "serial_number": cert["tbs_certificate"]["serial_number"],
                        }
                    )
                }
            ),
            "digest_algorithm": algos.DigestAlgorithm({"algorithm": hash_name}),
            "signed_attrs": signed_attrs,
            "signature_algorithm": algos.SignedDigestAlgorithm({"algorithm": sig_alg_oid}),
            "signature": signature,
        }
    )
    signed_data = cms.SignedData(
        {
            "version": "v3",
            "digest_algorithms": cms.DigestAlgorithms(
                [algos.DigestAlgorithm({"algorithm": hash_name})]
            ),
            "encap_content_info": cms.EncapsulatedContentInfo(
                {
                    "content_type": cms.ContentType(ID_MRTD_LDS_SECURITY_OBJECT),
                    "content": core.ParsableOctetString(econtent),
                }
            ),
            "certificates": cms.CertificateSet(
                [cms.CertificateChoices({"certificate": cert})]
            ),
            "signer_infos": cms.SignerInfos([signer_info]),
        }
    )
    return cms.ContentInfo({"content_type": "signed_data", "content": signed_data}).dump()
