"""Turns raw detections into a presales-readable analysis.

For every technology it answers three questions so a report can't be misread:
  * signal  - HOW we know (on the site / via a tag manager / only a link / DNS / domain verification / implied)
  * level   - how sure we are (Cao / Trung bình / Thấp)
  * group   - which business layer it belongs to (website platform, martech, CRM, ads, email, ...)
and it produces a per-domain summary, scan-quality verdict and vendor footprint.
"""
import re

from detector import CMS_CATS

# ------------------------------------------------------------------ vocab
SIGNALS = {
    "onsite": ("Trên website",
               "Mã, script, cookie hoặc header của công nghệ xuất hiện trực tiếp trên trang đã quét."),
    "tagmanager": ("Qua tag manager",
                   "Được cấu hình bên trong Google Tag Manager / Adobe Launch / Tealium. Có thể chỉ chạy ở một số "
                   "trang hoặc điều kiện, hoặc là tag cũ chưa gỡ."),
    "linked": ("Liên kết ra ngoài",
               "Website chỉ có đường link tới dịch vụ này (ví dụ cổng đại lý/đối tác). Bản thân website KHÔNG chạy "
               "trên nó, nhưng công ty có dùng dịch vụ."),
    "dns": ("DNS / email",
            "Thấy trong bản ghi DNS (MX, SPF, CNAME, NS): công ty dùng dịch vụ cho email hoặc hạ tầng, không nhất "
            "thiết liên quan tới website."),
    "verification": ("Chỉ xác thực domain",
                     "Chỉ có bản ghi TXT xác thực domain: công ty có (hoặc từng có) tài khoản dịch vụ, chưa chắc "
                     "đang dùng."),
    "implied": ("Suy luận", "Không thấy trực tiếp, suy ra từ một công nghệ khác."),
}
SIGNAL_ORDER = list(SIGNALS)

LEVELS = {
    "Cao": "Bằng chứng rõ (script/cookie/header/DNS đặc trưng, hoặc nhiều dấu hiệu độc lập).",
    "Trung bình": "Một dấu hiệu đơn lẻ trong mã trang, hoặc chỉ thấy trong tag manager.",
    "Thấp": "Chỉ xác thực domain hoặc suy luận; cần kiểm tra lại trước khi dùng.",
}

EV_LABELS = {
    "url": "URL", "html": "Mã HTML", "script": "File script", "inline-js": "Script nội tuyến",
    "cookie": "Cookie", "header": "HTTP header", "meta": "Thẻ meta", "generator": "Thẻ generator",
    "container": "Trong tag manager", "implied": "Suy ra từ",
    "dns-MX": "DNS MX", "dns-TXT": "DNS TXT", "dns-CNAME": "DNS CNAME", "dns-NS": "DNS NS",
}
ONSITE_TYPES = {"url", "html", "script", "inline-js", "cookie", "header", "meta", "generator"}
STRONG_TYPES = {"script", "cookie", "header", "meta", "generator", "container", "dns-MX", "dns-CNAME", "dns-NS"}

# Business layers. First group (in this order) whose keyword matches any category wins.
GROUPS = [
    ("platform", "Nền tảng website", ("cms", "dxp", "headless", "ecommerce", "blog", "wiki", "website builder",
                                      "page builder", "static site", "web framework", "javascript framework",
                                      "programming language", "digital asset", "lms", "forum", "documentation",
                                      "generator")),
    ("ads", "Quảng cáo", ("advertis", "retargeting", "affiliate", "ad network")),
    ("martech", "Martech & dữ liệu khách hàng", ("analytics", "tag manager", "marketing", "cdp", "customer data",
                                                 "personali", "a/b", "segment", "survey", "heatmap",
                                                 "session replay", "feedback", "loyalty", "review",
                                                 "push notification")),
    ("crm", "CRM, bán hàng & CSKH", ("crm", "chat", "support", "help desk", "helpdesk", "ticket", "lead", "form",
                                     "scheduling", "appointment")),
    ("email", "Email, DNS & tài khoản", ("email", "webmail", "domain verification")),
    ("security", "Bảo mật & quyền riêng tư", ("consent", "cookie compliance", "privacy", "security", "captcha",
                                              "authentication", "waf", "bot")),
    ("infra", "Hosting, CDN & hạ tầng", ("cdn", "paas", "iaas", "hosting", "web server", "reverse prox",
                                         "load balanc", "cach", "ssl", "certificate", "dns", "database",
                                         "operating system", "container", "network", "monitoring", "rum",
                                         "performance")),
]
OTHER = ("other", "Thư viện & khác")
GROUP_LABELS = dict([(k, label) for k, label, _ in GROUPS] + [OTHER])

KEY_VENDORS = ["Adobe", "Salesforce", "Sitecore", "HubSpot", "Oracle", "Optimizely", "SAP", "Acquia",
               "Bloomreach", "Microsoft", "Google"]

_BLOCK_TITLE = re.compile(r"just a moment|attention required|access denied|client challenge|application blocked|"
                          r"request rejected|forbidden|captcha|are you a robot|security check|bot verification|"
                          r"pardon our interruption|incapsula|ddos-guard", re.I)


# ------------------------------------------------------------- helpers
def normalize_evidence(e):
    """Structured evidence; also upgrades the string format stored by older scans."""
    if isinstance(e, dict):
        return {"type": e.get("type"), "value": e.get("value", ""), "page": e.get("page"), "via": e.get("via")}
    s, page, via = str(e), None, None
    m = re.match(r"\[(.*?)\] (.*)", s)
    if m:
        page, s = m.groups()
    kind, _, val = s.partition(": ")
    if kind.startswith("via "):
        kind, via = "container", kind[4:]
    elif kind.startswith("dns "):
        kind = "dns-" + kind[4:]
    elif kind == "meta/header generator":
        kind = "generator"
    elif kind == "implied":
        val = val.removeprefix("by ")
    return {"type": kind, "value": val, "page": page, "via": via}


def group_of(categories):
    cats = [c.lower() for c in categories]
    for key, _, words in GROUPS:
        if any(w in c for c in cats for w in words):
            return key
    return OTHER[0]


def signal_of(tech, evidence):
    if tech.get("relation") == "linked" or "(linked portal)" in tech["name"]:
        return "linked"
    types = {e["type"] for e in evidence}
    if types & ONSITE_TYPES:
        return "onsite"
    if "container" in types:
        return "tagmanager"
    dns = [e for e in evidence if (e["type"] or "").startswith("dns-")]
    if any(e["type"] in ("dns-MX", "dns-CNAME", "dns-NS") or e["value"].lower().startswith("v=spf1") for e in dns):
        return "dns"
    if dns:
        return "verification"
    return "implied"


def level_of(tech, evidence, signal):
    if signal in ("verification", "implied"):
        return "Thấp"
    if signal == "linked":
        return "Cao"
    types = {e["type"] for e in evidence}
    # a vendor-specific URL inside the HTML (form action, asset host) is as telling as a script tag
    url_in_html = any(e["type"] == "html" and re.search(r"[\w-]+\.[a-z]{2,}(?:\.[a-z]{2,})?/", e["value"])
                      for e in evidence)
    if tech["confidence"] >= 100 and (types & STRONG_TYPES or url_in_html or len(evidence) >= 2):
        return "Cao"
    return "Trung bình" if tech["confidence"] >= 50 else "Thấp"


def _where(evidence):
    pages = []
    for e in evidence:
        if e["type"] in ONSITE_TYPES:
            p = e["page"] or "trang chủ"
            if p not in pages:
                pages.append(p)
    return pages


def _vias(evidence):
    return sorted({e["via"] for e in evidence if e.get("via")})


def _link_target(evidence):
    for e in evidence:
        m = re.match(r"https?://([^/\s]+)(/[^\s]*)?", e["value"])
        if m:
            return m.group(0)
    return None


def scan_quality(result, techs):
    code, title = result.get("status_code"), result.get("title") or ""
    pages = len(result.get("pages") or [])
    failed = result.get("pages_failed") or []
    if not result.get("ok"):
        return {"key": "unreachable", "label": "Không truy cập được",
                "note": "Website không phản hồi. Chỉ phân tích được bản ghi DNS (email, xác thực domain)."}
    if code in (401, 403, 429, 503) or _BLOCK_TITLE.search(title):
        return {"key": "blocked", "label": "Bị chặn",
                "note": f"Website trả về {'HTTP ' + str(code) if code else ''}{' / ' if code and title else ''}"
                        f"{('trang “' + title[:60] + '”') if title else ''} — có tường lửa/chống bot. "
                        "Kết quả chủ yếu từ DNS và header nên có thể thiếu nhiều công nghệ."}
    if code and code >= 400:
        return {"key": "http_error", "label": f"Lỗi HTTP {code}",
                "note": "Trang chủ trả lỗi; kết quả có thể không đại diện cho website thật."}
    onsite = [t for t in techs if t["signal"] in ("onsite", "tagmanager")]
    if len(onsite) <= 2:
        return {"key": "thin", "label": "Ít dữ liệu",
                "note": "Tải được trang nhưng gần như không có dấu hiệu công nghệ: có thể là trang bảo trì, trang "
                        "render hoàn toàn bằng JavaScript, hoặc domain đỗ/chuyển hướng."}
    note = f"Đã quét trang chủ và {pages - 1} trang con." if pages > 1 else "Đã quét trang chủ (không tìm thấy trang con phù hợp)."
    if failed:
        note += f" {len(failed)} trang con không tải được."
    return {"key": "full", "label": "Đầy đủ", "note": note}


def _names(items, limit=8):
    names = [i["name"] + (" (qua tag manager)" if i["signal"] == "tagmanager" else "") for i in items]
    return ", ".join(names[:limit]) + (f" và {len(names) - limit} công nghệ khác" if len(names) > limit else "")


def _short(t):
    """'Salesforce Web-to-Lead' -> 'Web-to-Lead' when listed under the Salesforce vendor."""
    name = t["name"].replace(" (linked portal)", "")
    v = t.get("vendor") or ""
    short = name[len(v):].strip(" -") if v and name.startswith(v + " ") else name
    return short or name


def _product_phrase(t):
    sig = SIGNALS[t["signal"]][0].lower()
    name = _short(t)
    if t["signal"] == "linked":
        target = _link_target(t["evidence"])
        return f"{name} ({sig}" + (f": {target})" if target else ")")
    if t["signal"] == "onsite" and t["where"] and t["where"] != ["trang chủ"]:
        return f"{name} ({sig}, trang {', '.join(t['where'])})"
    if t["signal"] == "tagmanager":
        return f"{name} ({sig}" + (f": {', '.join(t['via'])})" if t["via"] else ")")
    return f"{name} ({sig})"


# ---------------------------------------------------------------- main
def analyze(result):
    techs = []
    for raw in result.get("technologies") or []:
        ev = [normalize_evidence(e) for e in raw.get("evidence") or []]
        sig = signal_of(raw, ev)
        g = group_of(raw.get("categories") or [])
        # A platform seen only inside a tag-manager container is just a URL mentioned there (e.g. a
        # medium.com link), not what the site runs on.
        if g == "platform" and sig == "tagmanager":
            g = OTHER[0]
        # A domain-verification TXT record only proves an account exists: it is an account signal,
        # whatever the product category (Canva, Notion, Atlassian...).
        if sig == "verification":
            g = "email"
        techs.append({
            "name": raw["name"], "vendor": raw.get("vendor"), "categories": raw.get("categories") or [],
            "is_cms": g == "platform" and (bool(CMS_CATS & set(raw.get("categories") or []))
                                           or raw["name"].startswith("Generator:")),
            "group": g, "group_label": GROUP_LABELS[g],
            "signal": sig, "signal_label": SIGNALS[sig][0],
            "level": level_of(raw, ev, sig), "confidence": raw.get("confidence", 0),
            "where": _where(ev), "via": _vias(ev),
            "evidence": [dict(e, label=EV_LABELS.get(e["type"], e["type"])) for e in ev],
        })
    # Something implied by a technology that isn't actually on the site inherits that doubt.
    sig_by_name = {t["name"]: t["signal"] for t in techs}
    for t in techs:
        parents = [e["value"] for e in t["evidence"] if e["type"] == "implied"]
        if t["signal"] == "implied" and parents and all(sig_by_name.get(p) != "onsite" for p in parents):
            t["group"], t["group_label"], t["is_cms"] = OTHER[0], OTHER[1], False

    # Drop a bare vendor entry ("Adobe", "Salesforce") when a more specific product of the same vendor
    # is backed by exactly the same evidence, e.g. one adobe-idp-site-verification TXT record.
    def _vals(t):
        return {(e["type"], e["value"]) for e in t["evidence"]}
    techs = [t for t in techs if not (t["vendor"] and t["name"] == t["vendor"] and any(
        o is not t and o["vendor"] == t["vendor"] and _vals(t) <= _vals(o) for o in techs))]
    techs.sort(key=lambda t: ([k for k, *_ in GROUPS + [OTHER]].index(t["group"]),
                              SIGNAL_ORDER.index(t["signal"]), t["name"].lower()))
    quality = scan_quality(result, techs)
    orgs = result.get("salesforce_org_ids") or []

    # vendor footprint
    vendors = {}
    for t in techs:
        if t["vendor"]:
            vendors.setdefault(t["vendor"], []).append(t)
    footprint = []
    for v in sorted(vendors, key=lambda v: (KEY_VENDORS.index(v) if v in KEY_VENDORS else 99, v)):
        items = sorted(vendors[v], key=lambda t: SIGNAL_ORDER.index(t["signal"]))
        footprint.append({
            "vendor": v, "key": v in KEY_VENDORS,
            "on_site": any(t["signal"] in ("onsite", "tagmanager") for t in items),
            "products": [{"name": t["name"], "signal": t["signal"], "signal_label": t["signal_label"],
                          "level": t["level"], "phrase": _product_phrase(t)} for t in items],
            "org_ids": orgs if v == "Salesforce" else [],
        })

    # summary bullets
    summary = []
    cms = [t for t in techs if t["is_cms"] and t["signal"] in ("onsite", "tagmanager")]
    real_cms = [t for t in cms if not t["name"].startswith("Generator:")]
    if real_cms:
        summary.append("Nền tảng website: " + ", ".join(
            t["name"] + (f" (chỉ ở trang {', '.join(t['where'])})" if t["where"] and "trang chủ" not in t["where"] else "")
            for t in real_cms) + ".")
    elif cms:
        summary.append("Trang tự khai báo generator: " + ", ".join(t["name"][11:] for t in cms)
                       + " (không có signature để xác minh).")
    elif quality["key"] in ("full", "thin"):
        base = [t["name"] for t in techs if t["group"] == "platform" and t["signal"] == "onsite"]
        summary.append("Chưa xác định được CMS: có thể là hệ thống tự phát triển, headless hoặc đã ẩn dấu vết."
                       + (f" Công nghệ nền thấy được: {', '.join(base[:6])}." if base else ""))
    ecom = [t for t in techs if "Ecommerce" in t["categories"] and t["signal"] == "onsite" and t not in cms]
    if ecom:
        summary.append("Thương mại điện tử: " + ", ".join(t["name"] for t in ecom) + ".")
    martech = [t for t in techs if t["group"] == "martech" and t["signal"] in ("onsite", "tagmanager")]
    if martech:
        summary.append("Martech trên website: " + _names(martech) + ".")
    cms_names = {t["name"] for t in real_cms}
    for f in footprint:
        if f["vendor"] in ("Microsoft", "Google") or not f["key"]:
            continue
        if all(p["name"] in cms_names for p in f["products"]) and not f["org_ids"]:
            continue  # already stated in the platform line
        line = f"{f['vendor']}: " + "; ".join(p["phrase"] for p in f["products"])
        if f["org_ids"]:
            line += "; Org ID " + ", ".join(o["id"] for o in f["org_ids"])
        summary.append(line + ".")
    mail = [t for t in techs if t["group"] == "email" and any(e["type"] == "dns-MX" for e in t["evidence"])]
    if mail:
        summary.append("Email doanh nghiệp (MX): " + ", ".join(t["name"] for t in mail) + ".")
    senders = [t for t in techs if t["signal"] == "dns" and t not in mail
               and any(e["value"].lower().startswith("v=spf1") for e in t["evidence"])]
    if senders:
        summary.append("Được phép gửi email thay domain (SPF): " + ", ".join(t["name"] for t in senders) + ".")
    ads = [t for t in techs if t["group"] == "ads" and t["signal"] in ("onsite", "tagmanager")]
    if ads:
        summary.append("Quảng cáo / pixel: " + _names(ads, 6) + ".")
    if quality["key"] != "full":
        summary.append("Lưu ý: " + quality["note"])

    groups = {}
    for t in techs:
        groups.setdefault(t["group"], []).append(t["name"])
    return {"quality": quality, "techs": techs, "groups": groups, "vendors": footprint,
            "summary": summary, "cms": [t["name"] for t in real_cms or cms]}


def aggregate(results):
    """Cross-domain view: per vendor and per technology, split by signal type."""
    vendors, techs = {}, {}
    for r in results:
        a = r["analysis"]
        for t in a["techs"]:
            e = techs.setdefault(t["name"], {"name": t["name"], "vendor": t["vendor"], "group": t["group"],
                                             "group_label": t["group_label"], "categories": t["categories"],
                                             "domains": {}})
            e["domains"][r["domain"]] = t["signal"]
        for f in a["vendors"]:
            v = vendors.setdefault(f["vendor"], {"vendor": f["vendor"], "key": f["key"], "domains": {},
                                                 "products": {}})
            v["domains"][r["domain"]] = "onsite" if f["on_site"] else min(
                (p["signal"] for p in f["products"]), key=SIGNAL_ORDER.index)
            for p in f["products"]:
                v["products"].setdefault(p["name"], {})[r["domain"]] = p["signal"]
    # Google / Microsoft show up on nearly every domain (analytics, M365), so list them after the
    # vendors that matter for positioning.
    vlist = sorted(vendors.values(), key=lambda v: (not v["key"], v["vendor"] in ("Google", "Microsoft"),
                                                    -len(v["domains"]), v["vendor"]))
    tlist = sorted(techs.values(), key=lambda t: (-len(t["domains"]), t["name"].lower()))
    quality = {}
    for r in results:
        k = r["analysis"]["quality"]["label"]
        quality[k] = quality.get(k, 0) + 1
    return {"vendors": vlist, "techs": tlist, "quality": quality,
            "signals": {k: {"label": v[0], "help": v[1]} for k, v in SIGNALS.items()},
            "levels": LEVELS, "groups": [{"key": k, "label": label} for k, label, _ in GROUPS] +
                                        [{"key": OTHER[0], "label": OTHER[1]}]}
