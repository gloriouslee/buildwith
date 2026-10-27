"""Wappalyzer-style technology detection engine.

Loads the curated martech signatures (signatures_martech.py) and, when present,
the community signatures downloaded by update_signatures.py into
data/signatures/.
"""
import fnmatch
import json
from pathlib import Path

import regex as re  # drop-in for `re`, but supports per-search timeouts (ReDoS guard)

from signatures_cms import SIGNATURES as CMS_SIGNATURES
from signatures_martech import SIGNATURES as MARTECH_SIGNATURES

CURATED = (MARTECH_SIGNATURES, CMS_SIGNATURES)  # same-named entries are merged by _add

DATA = Path(__file__).parent / "data" / "signatures"

# First match wins. Used to tag technologies with a vendor family for lead signals.
VENDOR_RULES = [
    (r"^(Adobe|Marketo|Magento|Omniture|Neolane|Scene7)", "Adobe"),
    (r"^(Salesforce|Pardot|Demandware|ExactTarget|Evergage|Krux|Tableau)", "Salesforce"),
    (r"^(Sitecore|Boxever|Stylelabs)", "Sitecore"),
    (r"^HubSpot", "HubSpot"),
    (r"^(Oracle|Eloqua|Responsys|BlueKai)", "Oracle"),
    (r"^(Optimizely|Episerver)", "Optimizely"),
    (r"^Acquia", "Acquia"),
    (r"^(Microsoft|Bing|Azure|SharePoint|Clarity)", "Microsoft"),
    (r"^(Google|YouTube|DoubleClick)", "Google"),
    (r"^(Facebook|Meta )", "Meta"),
]

# Categories worth re-checking on sub-pages (contact / quote / dealer forms, chat, tracking).
FOCUS_KEYS = ("marketing", "crm", "chat", "lead", "customer data", "cdp", "analytics", "tag manager",
              "a/b", "personali", "survey", "form", "email", "feedback", "scheduling", "support",
              "ticket", "advertising", "retargeting", "affiliate", "loyalty", "segment")

CMS_CATS = {"CMS", "Headless CMS", "Blogs", "Wikis", "Static site generator", "DXP", "Website builders"}

KINDS = ("url", "html", "scriptSrc", "scripts", "css", "container")
KV_KINDS = ("headers", "cookies", "meta", "dns")


def _as_list(v):
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


def _pat(p):
    """Compile a Wappalyzer pattern ('regex\\;confidence:50'). Returns (re, conf) or None."""
    parts = str(p).split("\\;")
    conf = 100
    for tag in parts[1:]:
        if tag.startswith("confidence:"):
            try:
                conf = int(tag.split(":", 1)[1])
            except ValueError:
                pass
    try:
        return re.compile(parts[0], re.I), conf
    except re.error:
        return None


def _pats(v):
    return [x for x in (_pat(p) for p in _as_list(v)) if x]


def _s(rx, text):
    """rx.search with a time limit: a pathological community pattern must not hang a scan."""
    try:
        return rx.search(text, timeout=1.0)
    except TimeoutError:
        return None


def _vendor_for(name):
    for rx, vendor in VENDOR_RULES:
        if re.search(rx, name, re.I):
            return vendor
    return None


class Detector:
    def __init__(self):
        self.techs = {}
        self.sources = {"curated": 0, "community": 0}
        self.load()

    # ---- loading -------------------------------------------------------
    def load(self):
        self.techs = {}
        cat_map = {}
        cat_file = DATA / "categories.json"
        if cat_file.exists():
            for cid, c in json.loads(cat_file.read_text(encoding="utf-8")).items():
                cat_map[str(cid)] = c.get("name", str(cid))
        community = 0
        tech_dir = DATA / "technologies"
        if tech_dir.exists():
            for f in sorted(tech_dir.glob("*.json")):
                try:
                    data = json.loads(f.read_text(encoding="utf-8"))
                except (OSError, ValueError):
                    continue
                for name, d in data.items():
                    self._add(name, d, cat_map)
                    community += 1
        for source in CURATED:
            for name, d in source.items():
                self._add(name, d, cat_map)
        self.sources = {"curated": sum(len(s) for s in CURATED), "community": community}
        curated = {n for s in CURATED for n in s}
        self.focus = {n for n, t in self.techs.items()
                      if n in curated or any(k in c.lower() for c in t["cats"] for k in FOCUS_KEYS)}

    def _add(self, name, d, cat_map):
        t = self.techs.get(name)
        if t is None:
            t = {"name": name, "cats": [], "vendor": None, "implies": [],
                 "rules": {k: [] for k in KINDS}, "kv": {k: {} for k in KV_KINDS}}
            self.techs[name] = t
        for c in _as_list(d.get("cats")):
            label = cat_map.get(str(c), str(c))
            if label not in t["cats"]:
                t["cats"].append(label)
        t["vendor"] = d.get("vendor") or t["vendor"] or _vendor_for(name)
        # "linked": the site only links to the service (e.g. a partner portal), it does not run it
        t["relation"] = d.get("relation") or t.get("relation")
        for imp in _as_list(d.get("implies")):
            p = _pat(imp)
            if p:
                t["implies"].append((str(imp).split("\\;")[0], p[1]))
        for k in KINDS:
            t["rules"][k] += _pats(d.get(k))
        # Inside tag-manager containers only domain-anchored script URLs are reliable: the
        # container runtime itself is full of generic code (jQuery, s.t(), require...).
        for p in _as_list(d.get("scriptSrc")):
            if re.search(r"\\\.(?:com|net|io|org|ms|eu|cloud|co|ai|app|tv|fm)\b", str(p)):
                c = _pat(p)
                if c:
                    t["rules"]["container"].append(c)
        for k in KV_KINDS:
            for key, val in (d.get(k) or {}).items():
                t["kv"][k].setdefault(key.lower(), []).extend(_pats(val))

    # ---- detection -----------------------------------------------------
    def detect(self, page, only=None):
        """page: url, html, headers{}, cookies{}, scripts[], inline_scripts, meta{}, dns{}, containers[(label,text)]
        only: optional set of technology names to restrict matching to (used for sub-pages)."""
        found = {}

        def hit(name, kind, value, conf, via=None):
            """kind: url, html, script, inline-js, cookie, header, meta, dns-MX/TXT/CNAME/NS,
            container (via = container label), implied, generator."""
            f = found.setdefault(name, {"evidence": [], "confidence": 0})
            ev = {"type": kind, "value": str(value)[:200], "via": via, "page": None}
            if not any(e["type"] == kind and e["value"] == ev["value"] for e in f["evidence"]) \
                    and len(f["evidence"]) < 6:
                f["evidence"].append(ev)
            f["confidence"] = min(100, f["confidence"] + conf)

        url = page.get("url", "")
        html = page.get("html", "")
        inline = page.get("inline_scripts", "")
        srcs = page.get("scripts", [])
        headers = page.get("headers", {})
        cookies = page.get("cookies", {})
        meta = page.get("meta", {})
        dns = page.get("dns", {})
        containers = page.get("containers", [])

        for name, t in self.techs.items():
            if only is not None and name not in only:
                continue
            r = t["rules"]
            for rx, conf in r["url"]:
                m = _s(rx, url)
                if m:
                    hit(name, "url", m.group(0), conf)
            for rx, conf in r["html"] + r["css"]:
                m = _s(rx, html)
                if m:
                    hit(name, "html", m.group(0), conf)
            for rx, conf in r["scriptSrc"]:
                for s in srcs:
                    if _s(rx, s):
                        hit(name, "script", s[-100:], conf)
                        break
            for rx, conf in r["scripts"]:
                m = _s(rx, inline)
                if m:
                    hit(name, "inline-js", m.group(0), conf)
            for label, text in containers:
                for rx, conf in r["container"]:
                    m = _s(rx, text)
                    if m:
                        hit(name, "container", m.group(0), min(conf, 80), via=label)
                        break
            kv = t["kv"]
            for hname, pats in kv["headers"].items():
                val = headers.get(hname)
                if val is None:
                    continue
                for rx, conf in pats:
                    if _s(rx, val):
                        hit(name, "header", f"{hname}: {val}", conf)
                        break
            for cname, pats in kv["cookies"].items():
                for have, val in cookies.items():
                    if have == cname or ("*" in cname and fnmatch.fnmatch(have, cname)):
                        if any(_s(rx, val) for rx, _ in pats):
                            hit(name, "cookie", have, pats[0][1])
                        break
            for mname, pats in kv["meta"].items():
                for val in meta.get(mname, []):
                    for rx, conf in pats:
                        if _s(rx, val):
                            hit(name, "meta", f"{mname}={val}", conf)
                            break
            for rtype, pats in kv["dns"].items():
                for val in dns.get(rtype.upper(), []):
                    for rx, conf in pats:
                        if _s(rx, val):
                            hit(name, f"dns-{rtype.upper()}", val, conf)
                            break

        # implied technologies
        for name in list(found):
            for imp, conf in self.techs[name]["implies"]:
                if imp in self.techs and imp not in found:
                    hit(imp, "implied", name, conf)

        out = []
        for name, f in found.items():
            if f["confidence"] < 50:  # a lone weak hint (e.g. a generic path) is not enough
                continue
            t = self.techs[name]
            out.append({"name": name, "categories": t["cats"], "vendor": t["vendor"], "relation": t["relation"],
                        "confidence": f["confidence"], "evidence": f["evidence"]})

        # Fallback for CMSs we have no signature for: surface the self-declared generator.
        known = " ".join(found).lower()
        gens = list(meta.get("generator", [])) + ([headers["x-generator"]] if headers.get("x-generator") else [])
        if only is not None or any(CMS_CATS & set(o["categories"]) for o in out):
            gens = []  # a CMS was already identified; extra generator tags are mostly plugins
        for g in gens:
            g = g.strip()
            word = re.split(r"[\s/_:,;-]", g.lower(), maxsplit=1)[0] if g else ""
            if len(word) < 3 or word in known:
                continue
            out.append({"name": f"Generator: {g[:60]}", "categories": ["CMS (generator tag)"], "vendor": None,
                        "relation": None, "confidence": 60,
                        "evidence": [{"type": "generator", "value": g[:200], "via": None, "page": None}]})
        out.sort(key=lambda x: (x["vendor"] is None, x["name"].lower()))
        return out
