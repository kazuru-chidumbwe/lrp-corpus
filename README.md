# LDS Reference Profiles (LRP)

**Status:** early release — schema, exemplar manifests, and hash-verify tooling only. On-chip profile bytes are not yet published.

Open, fault-injected corpus of **synthetic** eMRTD Logical Data Structure (LDS) artefacts for laboratory conformance and layer-tagged fault testing (writer / chip / reader-implicating).

Related software: [emrtd-differential-harness](https://github.com/kazuru-chidumbwe/emrtd-differential-harness) — reader negotiation observability (separate line of work; not required to use this corpus).

---

## Scope and safety

**All artifacts in this repository are synthetic.**

- No live country signing keys
- No real personal data
- No operational travel documents

Profiles are **deliberately non-conformant reference material** for laboratory conformance testing. They are **not** usable as, and do **not** constitute, forged travel documents.

---

## What is LRP?

**LDS Reference Profiles (LRP)** are versioned bundles of on-chip EF bytes plus a machine-readable manifest. Each profile documents **one primary fault** tagged by layer:

| Arm | Role |
| --- | --- |
| **Writer** | Injected LDS / encoding / trust-chain fault in document output |
| **Chip** | Modelled read-path behaviour on a software simulator |
| **Reader-implicating** | Conformant-but-uncommon encodings that stress reader/IS parsers |

### Profile ID convention

Manifest `profile_id` values use four prefixes (golden is a **control**, not an attribution arm):

```
lrp-{golden|writer|chip|reader}-{fault-slug}-{nnn}
```

| Prefix | Meaning |
| --- | --- |
| `golden` | Conformant control profile for golden-pair fault isolation |
| `writer` | Writer-arm fault injection |
| `chip` | Chip read-path fault (simulator) |
| `reader` | Reader-implicating conformant-but-uncommon encoding |

Examples: `lrp-golden-baseline-001`, `lrp-writer-trustchain-dsc-expired-001`, `lrp-chip-readpath-sw616c-001`, `lrp-reader-39794-dg2-7f2e-001`.

---

## Determinism

Lab PKI is generated from fixed seeds with fixed serials and distinguished names. Certificate validity windows are **absolute**, not relative to generation time; profiles requiring a specific verification instant pin `validation_time` in the manifest.

Every `.bin` has a stable SHA-256 across regenerations, recorded in the manifest when bytes are published.

---

## Repository layout

```
schema/           JSON Schema for profile manifests (v1) + exemplar manifests
profiles/         Profile bundles (manifest.json + EF *.bin) — not yet populated
scoring/          Reserved for scoring helpers
pki/              Reserved for synthetic lab CSCA/DSC/CRL material
tools/            Doc 9303-10 SOD hash verify / recompute CLI (CI selftest)
```

**Current state:** schema, **nine exemplar manifests** (`schema/examples/`), and verify tooling.

### Exemplar manifests (`schema/examples/`)

| File | Profile |
| --- | --- |
| `lrp-golden-baseline-001.json` | Golden control (5F2E DG2, EF.COM) |
| `lrp-writer-hash-dg2-001.json` | Writer — DG2 hash fault |
| `lrp-writer-trustchain-dsc-expired-001.json` | Writer — DSC expired at `validation_time` |
| `lrp-reader-sodlisted-dg3-001.json` | Reader-implicating — DG3 SOD-listed, BAC-only unreadable |
| `lrp-chip-readpath-sw616c-001.json` | Chip — READ BINARY returns `6Cxx` |
| `lrp-reader-39794-dg2-7f2e-001.json` | Reader — 39794 / `7F2E` DG2 |
| `lrp-reader-lds18-sod-primary-001.json` | Reader — LDS 1.8 SOD-primary parsing |
| `lrp-reader-ber-longlength-dg2-001.json` | Reader — BER-TLV long-form length |
| `lrp-reader-extended-lc-le-001.json` | Reader — extended Lc/Le |

Reader-implicating manifests include normative `conformance_basis` fields. On-chip bytes are **not** committed yet.

---

## Licences

| Path | Licence | Covers |
| --- | --- | --- |
| `LICENSE` | MIT | Software: `scoring/`, `pki/` generators, CI, scripts |
| `LICENSE-DATA` | CC-BY-4.0 | Data: `profiles/`, `schema/`, exemplar manifests |

---

## Citation

See [`CITATION.cff`](CITATION.cff). A Zenodo DOI will be added when the corpus is deposited.

---

## Author

Seke Kazuru · [ORCID 0009-0002-4099-1059](https://orcid.org/0009-0002-4099-1059)
