#!/usr/bin/env python3
"""Verify or recompute EF.SOD dataGroupHashValue entries against on-disk EF bytes."""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path

from lds_hash import (
    EF_KEY_TO_DG,
    HASH_OID_TO_NAME,
    dg2_inner_after_75,
    extract_lds_from_ef_sod,
    hash_ef_bytes,
    hash_name_for_oid,
)

ROOT = Path(__file__).resolve().parent


@dataclass
class DgCheck:
    dg_number: int
    ef_key: str
    path: Path
    sod_hash: bytes | None
    computed_hash: bytes
    match: bool
    note: str = ""


def load_manifest_files(manifest_path: Path, blobs_dir: Path) -> dict[str, Path]:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    files = manifest.get("files", {})
    out: dict[str, Path] = {}
    for ef_key, rel in files.items():
        if not isinstance(rel, str):
            continue
        path = (blobs_dir / rel).resolve()
        if not path.is_file():
            raise FileNotFoundError(f"missing blob for {ef_key}: {path}")
        out[ef_key] = path
    return out


def resolve_inputs(
    *,
    manifest: Path | None,
    blobs_dir: Path | None,
    sod: Path | None,
    dg_paths: dict[int, Path],
) -> tuple[Path, dict[int, Path]]:
    if manifest and blobs_dir:
        files = load_manifest_files(manifest, blobs_dir)
        sod_path = files.get("EF.SOD")
        if not sod_path:
            raise ValueError("manifest files must include EF.SOD")
        dg_map: dict[int, Path] = {}
        for ef_key, dg_num in EF_KEY_TO_DG.items():
            if ef_key in files:
                dg_map[dg_num] = files[ef_key]
        return sod_path, dg_map
    if sod and dg_paths:
        return sod, dg_paths
    raise ValueError("provide --manifest + --blobs-dir, or --sod + --dg")


def compute_dg_hash(
    dg_number: int,
    ef_bytes: bytes,
    hash_oid: str,
    *,
    dg2_mode: str,
) -> tuple[bytes, str]:
    if dg_number == 2 and dg2_mode == "inner-after-75":
        payload = dg2_inner_after_75(ef_bytes)
        return hash_ef_bytes(hash_oid, payload), "DG2 hashed inner-after-0x75 (legacy wrong boundary)"
    return hash_ef_bytes(hash_oid, ef_bytes), "complete EF bytes (Doc 9303-10)"


def verify_bundle(
    sod_path: Path,
    dg_map: dict[int, Path],
    *,
    dg2_mode: str = "complete-ef",
) -> list[DgCheck]:
    sod_ef = sod_path.read_bytes()
    hash_oid, sod_hashes = extract_lds_from_ef_sod(sod_ef)
    sod_by_dg = {num: h for num, h in sod_hashes}

    checks: list[DgCheck] = []
    for dg_num, dg_path in sorted(dg_map.items()):
        ef_bytes = dg_path.read_bytes()
        computed, note = compute_dg_hash(dg_num, ef_bytes, hash_oid, dg2_mode=dg2_mode)
        sod_hash = sod_by_dg.get(dg_num)
        match = sod_hash is not None and sod_hash == computed
        ef_key = next((k for k, n in EF_KEY_TO_DG.items() if n == dg_num), f"DG{dg_num}")
        checks.append(
            DgCheck(
                dg_number=dg_num,
                ef_key=ef_key,
                path=dg_path,
                sod_hash=sod_hash,
                computed_hash=computed,
                match=match,
                note=note,
            )
        )

    for dg_num, sod_hash in sorted(sod_by_dg.items()):
        if dg_num not in dg_map:
            checks.append(
                DgCheck(
                    dg_number=dg_num,
                    ef_key=f"DG{dg_num}",
                    path=Path("(missing)"),
                    sod_hash=sod_hash,
                    computed_hash=b"",
                    match=False,
                    note="listed in SOD but no EF file supplied",
                )
            )
    return checks


def print_report(checks: list[DgCheck], hash_oid: str) -> int:
    hash_name = hash_name_for_oid(hash_oid)
    print(f"hash algorithm: {hash_name} ({hash_oid})")
    ok = True
    for c in checks:
        status = "OK" if c.match else "FAIL"
        if not c.match:
            ok = False
        sod_hex = c.sod_hash.hex() if c.sod_hash else "(none)"
        cmp_hex = c.computed_hash.hex() if c.computed_hash else "(n/a)"
        print(f"[{status}] {c.ef_key}  {c.path.name}")
        print(f"       SOD:       {sod_hex}")
        print(f"       computed:  {cmp_hex}")
        if c.note:
            print(f"       note:      {c.note}")
    return 0 if ok else 1


def cmd_verify(args: argparse.Namespace) -> int:
    sod_path, dg_map = resolve_inputs(
        manifest=args.manifest,
        blobs_dir=args.blobs_dir,
        sod=args.sod,
        dg_paths=args.dg_map,
    )
    hash_oid, _ = extract_lds_from_ef_sod(sod_path.read_bytes())
    checks = verify_bundle(sod_path, dg_map, dg2_mode=args.dg2_mode)
    return print_report(checks, hash_oid)


def cmd_recompute(args: argparse.Namespace) -> int:
    sod_path, dg_map = resolve_inputs(
        manifest=args.manifest,
        blobs_dir=args.blobs_dir,
        sod=args.sod,
        dg_paths=args.dg_map,
    )
    hash_oid, sod_hashes = extract_lds_from_ef_sod(sod_path.read_bytes())
    sod_by_dg = {num: h for num, h in sod_hashes}

    rows: list[dict[str, object]] = []
    for dg_num, dg_path in sorted(dg_map.items()):
        ef_bytes = dg_path.read_bytes()
        computed, note = compute_dg_hash(dg_num, ef_bytes, hash_oid, dg2_mode=args.dg2_mode)
        rows.append(
            {
                "dg_number": dg_num,
                "ef_key": next((k for k, n in EF_KEY_TO_DG.items() if n == dg_num), f"DG{dg_num}"),
                "file": str(dg_path),
                "sod_hash": sod_by_dg.get(dg_num, b"").hex(),
                "computed_hash": computed.hex(),
                "match": sod_by_dg.get(dg_num) == computed,
                "hash_oid": hash_oid,
                "hash_name": HASH_OID_TO_NAME.get(hash_oid, hash_oid),
                "note": note,
            }
        )

    out = {
        "sod": str(sod_path),
        "hash_oid": hash_oid,
        "dg_hashes": rows,
    }
    text = json.dumps(out, indent=2) + "\n"
    if args.output:
        args.output.write_text(text, encoding="utf-8")
        print(f"wrote {args.output}")
    else:
        print(text)
    return 0


def cmd_selftest(_: argparse.Namespace) -> int:
    import subprocess

    gen = ROOT / "gen_minimal_fixture.py"
    subprocess.run([sys.executable, str(gen)], check=True)
    fixture_dir = ROOT / "testdata" / "minimal"
    manifest = fixture_dir / "manifest.json"
    code = cmd_verify(
        argparse.Namespace(
            manifest=manifest,
            blobs_dir=fixture_dir,
            sod=None,
            dg_map={},
            dg2_mode="complete-ef",
        )
    )
    if code != 0:
        print("selftest: verify failed on golden fixture", file=sys.stderr)
        return code

    # Deliberate wrong-boundary check on DG2
    dg2 = (fixture_dir / "dg2.bin").read_bytes()
    hash_oid, _ = extract_lds_from_ef_sod((fixture_dir / "sod.bin").read_bytes())
    wrong = hash_ef_bytes(hash_oid, dg2_inner_after_75(dg2))
    right = hash_ef_bytes(hash_oid, dg2)
    if wrong == right:
        print("selftest: DG2 wrong boundary equals complete EF — unexpected", file=sys.stderr)
        return 1
    print("selftest: OK (golden verify + DG2 boundary discrimination)")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest="command", required=True)

    v = sub.add_parser("verify", help="check SOD DG hashes against EF files")
    v.add_argument("--manifest", type=Path, help="LRP manifest JSON")
    v.add_argument("--blobs-dir", type=Path, help="directory with EF blob files")
    v.add_argument("--sod", type=Path, help="EF.SOD file (manual mode)")
    v.add_argument("--dg", action="append", default=[], metavar="N:PATH", help="DG number and file")
    v.add_argument(
        "--dg2-mode",
        choices=("complete-ef", "inner-after-75"),
        default="complete-ef",
        help="hash boundary for DG2 (default: complete EF per Doc 9303-10)",
    )
    v.set_defaults(
        dg_map={},
        handler=cmd_verify,
    )

    r = sub.add_parser("recompute", help="emit computed DG hashes as JSON")
    r.add_argument("--manifest", type=Path)
    r.add_argument("--blobs-dir", type=Path)
    r.add_argument("--sod", type=Path)
    r.add_argument("--dg", action="append", default=[], metavar="N:PATH")
    r.add_argument("--output", type=Path, help="write JSON here (default stdout)")
    r.add_argument("--dg2-mode", choices=("complete-ef", "inner-after-75"), default="complete-ef")
    r.set_defaults(handler=cmd_recompute, dg_map={})

    t = sub.add_parser("selftest", help="generate minimal fixture and verify")
    t.set_defaults(handler=cmd_selftest)

    return p


def main() -> int:
    parser = build_parser()
    if len(sys.argv) == 1:
        parser.print_help()
        return 0
    args = parser.parse_args()
    dg_map: dict[int, Path] = {}
    for item in getattr(args, "dg", []) or []:
        num_s, _, path_s = item.partition(":")
        dg_map[int(num_s)] = Path(path_s)
    args.dg_map = dg_map
    return args.handler(args)


if __name__ == "__main__":
    raise SystemExit(main())
