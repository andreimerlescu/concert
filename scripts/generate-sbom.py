#!/usr/bin/env python3
"""Generate a CycloneDX 1.5 JSON SBOM from Go module metadata (zero dependencies)."""

import argparse
import datetime
import json
import subprocess
import sys
import uuid


def load_go_modules():
    out = subprocess.check_output(["go", "list", "-m", "-json", "all"], text=True)
    dec = json.JSONDecoder()
    idx = 0
    mods = []
    length = len(out)
    while idx < length:
        while idx < length and out[idx].isspace():
            idx += 1
        if idx >= length:
            break
        obj, end = dec.raw_decode(out, idx)
        mods.append(obj)
        idx = end
    return mods


def purl(path, version):
    if version:
        return f"pkg:golang/{path}@{version}"
    return f"pkg:golang/{path}"


def main():
    parser = argparse.ArgumentParser(description="Generate CycloneDX 1.5 SBOM for Concert")
    parser.add_argument("-o", "--output", default="bin/concert-sbom.cdx.json", help="Output SBOM JSON path")
    args = parser.parse_args()

    mods = load_go_modules()
    main_mod = next((m for m in mods if m.get("Main")), {"Path": "github.com/andreimerlescu/concert"})
    try:
        with open("VERSION", "r", encoding="utf-8") as f:
            app_version = f.read().strip()
    except OSError:
        app_version = "0.0.0-dev"

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
                "name": main_mod.get("Path", "github.com/andreimerlescu/concert"),
                "version": app_version,
                "licenses": [{"license": {"id": "Apache-2.0"}}],
                "purl": purl(main_mod.get("Path", "github.com/andreimerlescu/concert"), app_version),
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
