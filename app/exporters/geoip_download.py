#!/usr/bin/env python3
"""Init container: download DB-IP GeoIP databases into /geoip emptyDir."""
import gzip, os, shutil, sys, urllib.request
from datetime import datetime

GEOIP_DIR = os.environ.get("GEOIP_DIR", "/geoip")
BASE_URL   = "https://download.db-ip.com/free"
MONTH      = datetime.utcnow().strftime("%Y-%m")
DBS = ["dbip-city-lite", "dbip-asn-lite"]

os.makedirs(GEOIP_DIR, exist_ok=True)

for db in DBS:
    dest = os.path.join(GEOIP_DIR, f"{db}.mmdb")
    url  = f"{BASE_URL}/{db}-{MONTH}.mmdb.gz"
    print(f"Downloading {url} ...", flush=True)
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "atomicwatch/1.0"})
        with urllib.request.urlopen(req, timeout=120) as resp, \
             gzip.open(resp) as gz, \
             open(dest, "wb") as out:
            shutil.copyfileobj(gz, out)
        print(f"  → {dest} ({os.path.getsize(dest):,} bytes)", flush=True)
    except Exception as e:
        print(f"  ERROR: {e}", file=sys.stderr, flush=True)
        sys.exit(1)

print("GeoIP download complete.", flush=True)
