"""Download the community Wappalyzer signature set (enthec/webappanalyzer) into data/signatures/."""
import truststore
truststore.inject_into_ssl()  # use the Windows cert store (corporate TLS inspection proxies)

import requests
from pathlib import Path

BASE = "https://raw.githubusercontent.com/enthec/webappanalyzer/main/src/"
OUT = Path(__file__).parent / "data" / "signatures"


def update():
    (OUT / "technologies").mkdir(parents=True, exist_ok=True)
    for ch in "_abcdefghijklmnopqrstuvwxyz":
        r = requests.get(f"{BASE}technologies/{ch}.json", timeout=60)
        r.raise_for_status()
        (OUT / "technologies" / f"{ch}.json").write_bytes(r.content)
    r = requests.get(f"{BASE}categories.json", timeout=60)
    r.raise_for_status()
    (OUT / "categories.json").write_bytes(r.content)


if __name__ == "__main__":
    update()
    print("Signatures updated in", OUT)
