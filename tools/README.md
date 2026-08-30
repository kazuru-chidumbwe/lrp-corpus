# LRP tools — verify-dry-run / hash recompute

Doc 9303-10 **`dataGroupHashValue`** checks: hash is computed over the **complete EF bytes** of each Data Group (including outer tag/length where part of the on-chip file).

**Canonical location:** this directory in [`lrp-corpus`](https://github.com/kazuru-chidumbwe/lrp-corpus).

## Setup

```bash
cd tools
python -m pip install -r requirements.txt
```

## Commands

### Self-test (generates minimal fixture + verifies)

```bash
python verify_dry_run.py selftest
```

### Verify LRP manifest + blob directory

```bash
python verify_dry_run.py verify \
  --manifest ../schema/examples/lrp-golden-baseline-001.json \
  --blobs-dir testdata/minimal
```

(Exemplar manifests under `schema/examples/` are manifest-only until on-chip byte files are published.)

### Verify ad hoc files

```bash
python verify_dry_run.py verify \
  --sod testdata/minimal/sod.bin \
  --dg 1:testdata/minimal/dg1.bin \
  --dg 2:testdata/minimal/dg2.bin
```

### Recompute hashes (JSON sidecar for SOD rebuild)

```bash
python verify_dry_run.py recompute \
  --manifest testdata/minimal/manifest.json \
  --blobs-dir testdata/minimal \
  --output testdata/minimal/dg-hashes.json
```

### DG2 boundary diagnostic (legacy wrong hash)

```bash
python verify_dry_run.py verify --sod ... --dg 2:dg2.bin --dg2-mode inner-after-75
```

Use **`complete-ef`** (default) for normative checks. **`inner-after-75`** demonstrates the withdrawn hash-boundary error.

## Files

| File | Role |
| --- | --- |
| `lds_hash.py` | EF.SOD parse, complete-EF hash, minimal CMS/LDS SO builder |
| `verify_dry_run.py` | CLI: `verify` · `recompute` · `selftest` |
| `gen_minimal_fixture.py` | Writes `testdata/minimal/` golden blobs |
| `testdata/minimal/` | Committed self-test fixture |

## CI

GitHub Actions runs `python verify_dry_run.py selftest` on push/PR (see `.github/workflows/verify.yml`).

## Exit codes

- `verify`: **0** all listed DGs match SOD; **1** any mismatch or missing EF for SOD-listed DG
- `recompute`: **0** always (inspect JSON `match` fields)
- `selftest`: **0** on pass

## Scope

- **In scope:** DG hash list vs EF bytes; SHA-1/256/384/512 OIDs in SOD
- **Out of scope:** CMS signature re-sign; trust-chain validation
