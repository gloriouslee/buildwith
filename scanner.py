"""Fetch a domain (HTTP + DNS + tag-manager containers) and run detection."""
import html as html_lib
import re
import time
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urljoin, urlparse

import dns.resolver
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/124.0 Safari/537.36")
MAX_HTML = 1_500_000
MAX_CONTAINER = 1_500_000
MAX_DOMAINS = 1000

_DOMAIN_RE = re.compile(r"^[^\s/]+\.[^\s/]+$")


def normalize(s):
    s = s.strip().lower()
    s = re.sub(r"^[a-z][a-z0-9+.-]*://", "", s)
    s = re.split(r"[/?#]", s)[0].split("@")[-1].split(":")[0].strip(".")
    return s if _DOMAIN_RE.match(s) else None


def parse_domains(text):
    seen, out = set(), []
    for tok in re.split(r"[\s,;]+", text or ""):
        d = normalize(tok)
        if d and d not in seen:
            seen.add(d)
            out.append(d)
    return out[:MAX_DOMAINS]


def dns_lookup(host):
    base = host[4:] if host.startswith("www.") else host
    res = dns.resolver.Resolver()
    res.lifetime, res.timeout = 4, 2
    out = {"MX": [], "TXT": [], "NS": [], "CNAME": []}

    def q(name, rtype):
        try:
            vals = []
            for r in res.resolve(name, rtype):
                if rtype == "MX":
                    vals.append(str(r.exchange).rstrip("."))
                elif rtype == "TXT":
                    vals.append(b"".join(r.strings).decode("utf-8", "replace"))
                elif rtype == "CNAME":
                    vals.append(str(r.target).rstrip("."))
                else:
                    vals.append(str(r).rstrip("."))
            return vals
        except Exception:
            return []

    out["MX"] = q(base, "MX")
    out["TXT"] = q(base, "TXT")
    out["NS"] = q(base, "NS")
    out["CNAME"] = q(host, "CNAME") + (q("www." + base, "CNAME") if host == base else [])
    return out


def _get(session, url, timeout, cap, budget=25):
    r = session.get(url, timeout=timeout, allow_redirects=True, verify=False, stream=True)
    chunks, size, deadline = [], 0, time.time() + budget
    for c in r.iter_content(65536):
        chunks.append(c)
        size += len(c)
        if size > cap or time.time() > deadline:  # cap size and total time (slow-drip servers)
            break
    r.close()
    body = b"".join(chunks)
    # requests defaults to ISO-8859-1 when the header has no charset, which garbles UTF-8 pages
    m = re.search(r"charset=([\w-]+)", r.headers.get("content-type", ""), re.I) \
        or re.search(rb"<meta[^>]+charset=[\"']?([\w-]+)", body[:4096], re.I)
    enc = (m.group(1).decode() if isinstance(m.group(1), bytes) else m.group(1)) if m else "utf-8"
    try:
        return r, body.decode(enc, errors="replace")
    except LookupError:  # charset Python doesn't know
        return r, body.decode("utf-8", errors="replace")


def _parse_html(html):
    scripts = re.findall(r"<script[^>]+src\s*=\s*[\"']([^\"']+)[\"']", html, re.I)
    inline = "\n".join(re.findall(r"<script(?![^>]*\bsrc=)[^>]*>(.*?)</script>", html, re.I | re.S))[:400_000]
    meta = {}
    for tag in re.findall(r"<meta\b[^>]*>", html, re.I):
        a = {}
        for m in re.finditer(r"([\w:-]+)\s*=\s*(?:\"([^\"]*)\"|'([^']*)')", tag):
            a[m.group(1).lower()] = m.group(2) if m.group(2) is not None else m.group(3)
        key = (a.get("name") or a.get("property") or "").lower()
        if key and "content" in a:
            meta.setdefault(key, []).append(a["content"])
    m = re.search(r"<title[^>]*>(.*?)</title>", html, re.I | re.S)
    title = html_lib.unescape(re.sub(r"\s+", " ", m.group(1))).strip()[:160] if m else ""
    return scripts, inline, meta, title


_TM_URL = re.compile(r"(?:https?:)?//(?:assets\.adobedtm\.com/[^\"'\s\\]*launch-[^\"'\s\\]*\.js"
                     r"|tags\.tiqcdn\.com/utag/[^\"'\s\\]+\.js)")


def _fetch_containers(session, html, scripts):
    """Download tag-manager containers: their contents reveal tags not present in the HTML."""
    out = []
    for gid in list(dict.fromkeys(re.findall(r"GTM-[A-Z0-9]{4,}", html)))[:2]:
        try:
            _, text = _get(session, f"https://www.googletagmanager.com/gtm.js?id={gid}", (5, 10), MAX_CONTAINER)
            out.append((f"GTM {gid}", text.replace("\\/", "/")))  # GTM stores URLs JSON-escaped
        except Exception:
            pass
    # Launch / Tealium libraries: from the page itself, and from inside GTM (GTM often loads them)
    pool = list(scripts) + [u for _, text in out for u in _TM_URL.findall(text)]
    seen = set()
    for src in pool:
        if not _TM_URL.fullmatch(src):
            continue
        url = "https:" + src if src.startswith("//") else src
        if url in seen:
            continue
        seen.add(url)
        label = "Adobe Launch" if "adobedtm" in url else "Tealium"
        try:
            _, text = _get(session, url, (5, 10), MAX_CONTAINER)
            out.append((label, text))
        except Exception:
            pass
        if len(seen) >= 3:
            break
    return out


_worker_detector = None


def init_worker():
    """Process-pool initializer: each worker process loads its own detector once."""
    global _worker_detector
    from detector import Detector
    _worker_detector = Detector()


def scan_in_worker(host):
    return scan_domain(host, _worker_detector)


def scan_domain(host, detector):
    t0 = time.time()
    result = {"domain": host, "ok": False, "status_code": None, "final_url": None, "title": "",
              "error": None, "technologies": [], "dns": {}, "containers": [], "pages": [],
              "salesforce_org_ids": []}
    try:
        result["dns"] = dns_lookup(host)
    except Exception as e:  # DNS must never kill the scan
        result["dns"] = {}
        result["error"] = f"dns: {e}"

    session = requests.Session()
    session.headers.update({"User-Agent": UA, "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
                            "Accept-Language": "en-US,en;q=0.9"})
    urls = [f"https://{host}", f"http://{host}"]
    if not host.startswith("www."):
        urls.append(f"https://www.{host}")

    resp, html, last_err = None, "", None
    for u in urls:
        try:
            resp, html = _get(session, u, (6, 15), MAX_HTML)
            break
        except Exception as e:
            last_err = e
    if resp is None:
        result["error"] = f"Không truy cập được: {type(last_err).__name__}"
        # DNS-only detection still has value (MX / TXT / CNAME)
        page = {"dns": {k.upper(): v for k, v in result["dns"].items()}}
        result["technologies"] = detector.detect(page)
        result["salesforce_org_ids"] = salesforce_org_ids([], page["dns"].get("TXT", []))
        result["elapsed"] = round(time.time() - t0, 1)
        return result

    scripts, inline, meta, title = _parse_html(html)
    containers = _fetch_containers(session, html, scripts)
    subpages, sub_failed = _fetch_subpages(session, resp.url, html)
    dns_up = {k.upper(): v for k, v in result["dns"].items()}
    page = {
        "url": resp.url, "html": html, "inline_scripts": inline, "scripts": scripts, "meta": meta,
        "headers": {k.lower(): v for k, v in resp.headers.items()},
        "cookies": {c.name.lower(): c.value for c in session.cookies},
        "dns": dns_up,
        "containers": containers,
    }
    techs = detector.detect(page)

    # Sub-pages: only martech-type signatures, and only for technologies not already found.
    found = {t["name"] for t in techs}
    for url, sub_html in subpages:
        s_scripts, s_inline, _, _ = _parse_html(sub_html)
        path = urlparse(url).path or "/"
        for t in detector.detect({"url": url, "html": sub_html, "scripts": s_scripts,
                                  "inline_scripts": s_inline}, only=detector.focus - found):
            for e in t["evidence"]:
                e["page"] = path
            techs.append(t)
            found.add(t["name"])

    org_texts = [("trang chủ", html)] + [(urlparse(u).path, h) for u, h in subpages] + containers
    result.update(ok=True, status_code=resp.status_code, final_url=resp.url, title=title,
                  containers=[c[0] for c in containers], technologies=techs,
                  pages=[resp.url] + [u for u, _ in subpages],
                  pages_failed=[{"url": u, "reason": why} for u, why in sub_failed],
                  salesforce_org_ids=salesforce_org_ids(org_texts, dns_up.get("TXT", [])))
    result["error"] = None if resp.status_code < 400 else f"HTTP {resp.status_code}"
    result["elapsed"] = round(time.time() - t0, 1)
    return result


# ---------------------------------------------------------------- sub-pages
MAX_SUBPAGES = 5
_SUBPAGE_KEYS = re.compile(
    r"contact|lien-?he|quote|bao-?gia|dealer|dai-?ly|distributor|partner|demo|request|enquir|inquir|"
    r"newsletter|subscribe|sign-?up|register|dang-?ky|support|ho-?tro|book|trial|get-started", re.I)
_SKIP_EXT = re.compile(r"\.(?:pdf|jpe?g|png|gif|svg|webp|zip|docx?|xlsx?|pptx?|mp4|mp3)$", re.I)


def _pick_subpages(base_url, html):
    """Same-site links that typically carry lead forms, chat or partner portals."""
    host = urlparse(base_url).netloc.lower().split(":")[0]
    root = host[4:] if host.startswith("www.") else host
    picked = []
    for h in re.findall(r"<a\b[^>]*?href\s*=\s*[\"']([^\"'#]+)", html, re.I):
        p = urlparse(urljoin(base_url, h.strip()))
        n = p.netloc.lower().split(":")[0]
        if p.scheme not in ("http", "https") or not (n == root or n.endswith("." + root)):
            continue
        if _SKIP_EXT.search(p.path) or not _SUBPAGE_KEYS.search(p.path):
            continue
        u = p._replace(query="", fragment="").geturl()
        if u.rstrip("/") != base_url.rstrip("/") and u not in picked:
            picked.append(u)
    # hub pages first: /contact-us/ before /contact-us/thank-you/
    picked.sort(key=lambda u: (urlparse(u).path.strip("/").count("/"), len(u)))
    return picked[:MAX_SUBPAGES]


def _fetch_subpages(session, base_url, html):
    """Returns (fetched [(url, html)], failed [(url, reason)])."""
    def one(u):
        try:
            r, text = _get(session, u, (5, 10), MAX_HTML, budget=12)
            if r.status_code >= 400:
                return u, None, f"HTTP {r.status_code}"
            if "html" not in r.headers.get("content-type", "html"):
                return u, None, "không phải trang HTML"
            return u, text, None
        except Exception as e:
            return u, None, type(e).__name__

    urls = _pick_subpages(base_url, html)
    if not urls:
        return [], []
    with ThreadPoolExecutor(len(urls)) as ex:
        res = list(ex.map(one, urls))
    return [(u, t) for u, t, err in res if t is not None], [(u, err) for u, t, err in res if t is None]


# ----------------------------------------------------------- Salesforce org
_ORG = r"(00D[0-9A-Za-z]{12}(?:[0-9A-Za-z]{3})?)\b"
_ORG_PATTERNS = [
    (re.compile(r"servlet\.WebTo(?:Lead|Case)\?[^\"'\s>]*?\borgId=" + _ORG, re.I), "Web-to-Lead/Case form"),
    (re.compile(r"name=[\"'](?:oid|orgid)[\"'][^>]*?value=[\"']" + _ORG, re.I), "form field oid"),
    (re.compile(r"value=[\"']" + _ORG + r"[\"'][^>]*?name=[\"'](?:oid|orgid)[\"']", re.I), "form field oid"),
    (re.compile(r"(?:embeddedservice_bootstrap|embedded_svc|liveagent)\.init\([^)]{0,400}?[\"']" + _ORG, re.I | re.S),
     "chat / messaging"),
    (re.compile(r"[\"']?(?:orgId|organizationId|sfOrgId)[\"']?\s*[:=]\s*[\"']" + _ORG), "script config"),
]


def salesforce_org_ids(texts, txt_records):
    """Salesforce org IDs (00D…) found in forms, chat snippets, tag containers and DNS TXT.
    IDs are normalised to their 15-character form so 15/18-char variants merge."""
    found = {}  # org -> {source: [where, ...]}

    def add(org, source, where):
        places = found.setdefault(org[:15], {}).setdefault(source, [])
        if where and where not in places:
            places.append(where)

    for label, text in texts:
        for rx, source in _ORG_PATTERNS:
            for m in rx.finditer(text):
                add(m.group(1), source, label)
    for rec in txt_records:
        m = re.match(_ORG + "=", rec)
        if m:
            add(m.group(1), "DNS TXT verification", None)
    return [{"id": org, "sources": [f"{s}: {', '.join(w)}" if w else s for s, w in srcs.items()]}
            for org, srcs in found.items()]
