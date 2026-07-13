"""Download and parse MITRE ATT&CK STIX data into a compact techniques.json file."""

import json
import os
import sys
from pathlib import Path

STIX_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
DATA_DIR = Path(__file__).resolve().parent.parent / "src" / "data"
OUTPUT_FILE = DATA_DIR / "techniques.json"


def fetch_stix_bundle(url: str) -> dict:
    import requests
    print(f"Downloading STIX bundle from {url}...")
    resp = requests.get(url, timeout=120)
    resp.raise_for_status()
    return resp.json()


def build_techniques(bundle: dict) -> dict:
    objects = bundle.get("objects", [])

    tactics = {}
    platforms = {}
    techniques = {}

    for obj in objects:
        if obj.get("type") == "x-mitre-tactic":
            tid = obj.get("x_mitre_shortname", "")
            name = obj.get("name", "")
            if tid:
                tactics[tid] = name

        if obj.get("type") == "attack-pattern":
            tid = obj.get("external_references", [{}])[0].get("external_id", "")
            if not tid:
                continue
            name = obj.get("name", "")
            desc = obj.get("description", "")[:500]
            url = obj.get("external_references", [{}])[0].get("url", "")
            kill_chain = obj.get("kill_chain_phases", [])
            tactic_refs = [
                p["phase_name"] for p in kill_chain
                if p.get("kill_chain_name") == "mitre-attack"
            ]
            tactic_names = [tactics.get(t, t) for t in tactic_refs]

            techniques[tid] = {
                "id": tid,
                "name": name,
                "tactics": tactic_names,
                "description": desc[:500],
                "url": url,
            }

        if obj.get("type") == "x-mitre-matrix":
            ps = obj.get("tactic_refs", [])
            # Not directly used but indicates tactic ordering
            pass

    return techniques


def main():
    try:
        bundle = fetch_stix_bundle(STIX_URL)
    except Exception as e:
        print(f"Error downloading STIX bundle: {e}", file=sys.stderr)
        print("Make sure you have network access and 'requests' installed.", file=sys.stderr)
        sys.exit(1)

    techniques = build_techniques(bundle)
    print(f"Extracted {len(techniques)} techniques/sub-techniques.")

    DATA_DIR.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(techniques, f, indent=2, ensure_ascii=False)

    print(f"Written to {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
