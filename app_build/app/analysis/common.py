from __future__ import annotations


def inflate_certs(doc: dict) -> dict:
    """Re-attach full certificate dicts (stored once in doc['certificates']) to each session's chain."""
    reg = doc.get("certificates", {})
    for s in doc["sessions"]:
        ch = s.get("chain")
        if ch and "fingerprints" in ch and "certificates" not in ch:
            ch["certificates"] = [reg[fp] for fp in ch["fingerprints"] if fp in reg]
    return doc
