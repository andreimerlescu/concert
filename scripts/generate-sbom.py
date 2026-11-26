#!/usr/bin/env python3
"""Generate a CycloneDX 1.5 JSON SBOM from Go module/package metadata (zero dependencies)."""

import argparse
import datetime
import json
import subprocess
import sys
import uuid


def decode_json_stream(text):
    dec = json.JSONDecoder()
    idx = 0
    objs = []
    length = len(text)
    while idx < length:
        while idx < length and text[idx].isspace():
            idx += 1
        if idx >= length:
            break
        obj, end = dec.raw_decode(text, idx)
        objs.append(obj)
        idx = end
    return objs


def load_go_modules(pkg=None, tags=None):
    if pkg:
        cmd = ["go", "list", "-deps", "-json"]
        if tags:
            cmd.extend(["-tags", tags])
        cmd.append(pkg)
        pkgs = decode_json_stream(subprocess.check_output(cmd, text=True))
        seen = {}
        for p in pkgs:
            m = p.get("Module")
            if not m:
                continue
            path = m.get("Path", "")
            if path and path not in seen:
                seen[path] = m
        return sorted(seen.values(), key=lambda m: (not m.get("Main", False), m.get("Path", "")))
    out = subprocess.check_output(["go", "list", "-m", "-json", "all"], text=True)
    return decode_json_stream(out)


def purl(path, version):
    if version:
        return f"pkg:golang/{path}@{version}"
    return f"pkg:golang/{path}"


def main():
    parser = argparse.ArgumentParser(description="Generate CycloneDX 1.5 SBOM for Concert")
    parser.add_argument("-o", "--output", default="bin/concert-sbom.cdx.json", help="Output SBOM JSON path")
    parser.add_argument("--pkg", default="", help="Optional target package (e.g. ./cmd/concert) to emit only linked modules")
    parser.add_argument("--tags", default="", help="Optional Go build tags (e.g. wordpress or wordpress,enterprise)")
    parser.add_argument("--name", default="", help="Optional component name override (e.g. wpconcert)")
    args = parser.parse_args()

    mods = load_go_modules(pkg=args.pkg or None, tags=args.tags or None)
    main_mod = next((m for m in mods if m.get("Main")), {"Path": "github.com/andreimerlescu/concert"})
    try:
        with open("VERSION", "r", encoding="utf-8") as f:
            app_version = f.read().strip()
    except OSError:
        app_version = "0.0.0-dev"

    comp_path = main_mod.get("Path", "github.com/andreimerlescu/concert")
    if args.name:
        comp_name = f"{comp_path}/cmd/{args.name}"
    else:
        comp_name = comp_path

    components = []
    for m in mods:
        if m.get("Main"):
            continue
        path = m.get("Path", "")
        ver = m.get("Version", "")
        if not path:
            continue
        comp = {
            "type": "library",
            "name": path,
            "version": ver,
            "purl": purl(path, ver),
            "bom-ref": purl(path, ver),
        }
        if m.get("Indirect"):
            comp["scope"] = "optional"
        else:
            comp["scope"] = "required"
        components.append(comp)

    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "component": {
                "type": "application",
                "name": comp_name,
                "version": app_version,
                "licenses": [{"license": {"id": "Apache-2.0"}}],
                "purl": purl(comp_name, app_version),
            },
        },
        "components": components,
    }

    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(sbom, f, indent=2)
        f.write("\n")
    print(f"Wrote CycloneDX 1.5 SBOM with {len(components)} components to {args.output}")


if __name__ == "__main__":
    sys.exit(main())
