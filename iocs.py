#!/usr/bin/python3
"""Indicators of compromise (IOCs) named in a threat report the AI read during research.

extract(text, ...) pulls attacker domains, URLs, public IPs and file hashes out of a web page's text (markdown from
webtools.fetch), so the event reviewer / researcher can hunt for them in this network's own logs (es_context.hunt via the
host broker POST /iochunt) and keep them on the event as "researched artifacts".

The page is untrusted: only strings that match strict indicator shapes come out, link / image targets (navigation,
the publisher's own CDN) are ignored, and well-known platform domains, the page's own site and the sources the AI already
has are dropped. Defanged forms (1688360[.]cc, hxxps://) are re-fanged.
"""
import ipaddress, os, re

MAX_IOCS = 20
THREAT_WORDS = re.compile(r"malware|malicious|attack|hijack|compromis|breach|campaign|ioc|indicator|phish|exploit|backdoor|"
                          r"botnet|c2\b|command.and.control|skimm|supply.chain|ransomware|trojan|stealer|threat|infect|payload", re.I)
# file extensions that look like TLDs in report text (track.js, card.php, README.md)
NOT_TLD = {"js", "mjs", "php", "html", "htm", "aspx", "asp", "jsp", "css", "json", "xml", "txt", "exe", "dll", "png", "jpg", "jpeg",
           "gif", "svg", "webp", "ico", "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "py", "sh", "ps1", "bat", "cmd", "vbs",
           "md", "yml", "yaml", "log", "conf", "cfg", "ini", "tar", "gz", "tgz", "rar", "7z", "so", "bin", "dat", "tmp", "csv",
           "mp4", "mp3", "wav", "mov", "avi", "jar", "apk", "ipa", "dmg", "pkg", "deb", "rpm", "msi", "lnk", "hta", "wasm", "map",
           "ts", "tsx", "jsx", "go", "rb", "java", "c", "h", "cpp", "rs", "pl", "lock", "env", "key", "pem", "crt", "sig", "zip"}
# platforms that appear in almost every article (sharing buttons, CDNs, references) - never an IOC on their own
BENIGN = {"google.com", "gstatic.com", "googleapis.com", "googleusercontent.com", "youtube.com", "microsoft.com", "windows.com",
          "office.com", "live.com", "apple.com", "icloud.com", "github.com", "githubusercontent.com", "gitlab.com", "twitter.com",
          "x.com", "t.co", "linkedin.com", "facebook.com", "fb.com", "instagram.com", "reddit.com", "cloudflare.com",
          "amazonaws.com", "amazon.com", "akamaihd.net", "website-files.com", "webflow.com", "wordpress.com", "wp.com",
          "medium.com", "calendly.com", "gravatar.com", "w3.org", "schema.org", "mozilla.org", "wikipedia.org", "example.com",
          "example.org", "example.net", "bit.ly", "hubspot.com", "hsforms.com", "doubleclick.net", "googletagmanager.com",
          "jquery.com", "bootstrapcdn.com", "fonts.net", "typekit.net", "mitre.org", "nist.gov", "cisa.gov", "virustotal.com"}
_DEFANG = [(re.compile(r"\\?\[\\?\.\\?\]|\(\.\)|\{\.\}|\\?\[dot\\?\]|\(dot\)", re.I), "."), (re.compile(r"\[:\]"), ":"),
           (re.compile(r"\bhxxp(s?)", re.I), r"http\1"), (re.compile(r"\bfxp\b", re.I), "ftp")]
_LINKS = re.compile(r"!\[[^\]]*\]\([^)]*\)|\]\((?:[^()]|\([^)]*\))*\)|<[^>]+>")  # markdown images, link targets, html tags
_URL = re.compile(r"\b(?:https?|ftp)://[^\s<>\"'`)\]|]+", re.I)
_DOM = re.compile(r"(?<![\w@.-])((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,23})(?![\w-]|\.[a-z0-9])", re.I)
_BARE = re.compile(r"(?<![\w@./-])((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,23})(/[\w./%-]*\.(?:js|php|exe|dll|ps1|sh|bin|apk|zip|html?|aspx?))\b", re.I)
_IP = re.compile(r"(?<![\d.])((?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3})(?![\d.])")
_HASH = re.compile(r"(?<![0-9a-fA-F])([0-9a-fA-F]{64}|[0-9a-fA-F]{40}|[0-9a-fA-F]{32})(?![0-9a-fA-F])")


try:  # real top-level domains only: "dope.console" or "track.js" in prose is not a domain
    with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "iocs_tlds.txt"), encoding="utf-8") as _f:
        TLDS = {ln.strip() for ln in _f if ln.strip() and not ln.startswith("#")}
except OSError:
    TLDS = set()
# a sentence that clears what it names ("... 104.18.65.57. These are delivery-resource associations, not malicious IP indicators")
_CLEARS = re.compile(r"not (?:a |an )?(?:malicious|attacker|indicator|ioc)|benign|legitimate|false positive|not related|clean", re.I)


def _sentences(text):
    return re.split(r"(?<=[.!?])\s+(?=[A-Z_*(])|\n{2,}", text)


def refang(s):
    for rx, rep in _DEFANG:
        s = rx.sub(rep, s)
    return s


def regdom(d):
    """Registrable domain (eTLD+1, approximate): a.b.example.co.uk -> example.co.uk, cdn.optimizely.com -> optimizely.com."""
    p = str(d).lower().strip(".").split(".")
    if len(p) >= 3 and len(p[-1]) == 2 and p[-2] in ("co", "com", "net", "org", "gov", "edu", "ac", "ne", "or", "go"):
        return ".".join(p[-3:])
    return ".".join(p[-2:])


def _host(url):
    m = re.match(r"(?:https?|ftp)://([^/:?#]+)", str(url or ""), re.I)
    return m.group(1).lower() if m else ""


def _ok_dom(d):
    t = d.rsplit(".", 1)[-1].lower()
    return t not in NOT_TLD and not t.isdigit() and len(d) <= 253 and "." in d and (not TLDS or t in TLDS)


def extract(text, page_url="", exclude=(), limit=MAX_IOCS):
    """Report text -> [{kind: dns|url|ip|hash, value, strong}] (strong = written as code, in a table or defanged).
    exclude: domains / IPs already known (the event's own, the AI's other sources): they and their sites are skipped."""
    raw = str(text or "")
    body = _LINKS.sub(" ", raw)
    defanged = {m.lower() for m in re.findall(r"[\w.-]*(?:\[\.\]|\(\.\)|\[dot\])[\w.\[\]()-]*", body, re.I)}
    body = refang(body)
    strong_txt = " ".join(re.findall(r"`([^`\n]{3,300})`", body) + [ln for ln in body.splitlines() if ln.lstrip().startswith("|")])
    strong_txt += " " + refang(" ".join(defanged))
    skip = {regdom(_host(page_url))} | BENIGN
    for x in exclude or ():
        x = str(x or "").lower().strip()
        if x:
            skip.add(x)
            if re.search(r"[a-z]", x):
                skip.add(regdom(_host(x) or x))
    found, order = {}, []

    def add(kind, value, strong):
        k = (kind, value)
        if k not in found:
            found[k] = {"kind": kind, "value": value, "strong": False, "n": 0}
            order.append(k)
        found[k]["strong"] |= strong
        found[k]["n"] += 1

    for src, strong in ((strong_txt, True), (body, False)):
        for u in _URL.findall(src):
            u = u.rstrip(".,;:!?*_")
            h = _host(u)
            if h and _ok_dom(h) and h not in skip and regdom(h) not in skip and _DOM.fullmatch(h):
                if "/" in u.split("://", 1)[1].rstrip("/"):
                    add("url", u[:300], strong)
                add("dns", h, strong)
        for h, path in _BARE.findall(_URL.sub(" ", src)):  # 1688360[.]cc/track.js written without a scheme
            h = h.lower()
            if _ok_dom(h) and h not in skip and regdom(h) not in skip:
                add("url", f"https://{h}{path}"[:300], strong)
                add("dns", h, strong)
        for d in _DOM.findall(_URL.sub(" ", src)):
            d = d.lower().rstrip(".")
            if _ok_dom(d) and d not in skip and regdom(d) not in skip:
                add("dns", d, strong)
        for ip in _IP.findall(src):
            try:
                if ipaddress.ip_address(ip).is_global and ip not in skip and not ip.endswith((".0", ".255")):  # a network, not a host
                    add("ip", ip, strong)
            except ValueError:
                pass
        for h in _HASH.findall(src):
            if re.search(r"[a-fA-F]", h) and re.search(r"\d", h):
                add("hash", h.lower(), strong)
    # a host that is only a sub-name of another listed IOC (www.x.cc next to x.cc) adds nothing for the hunt
    # what the report itself clears (named in a sentence or the line after a figure saying "not malicious", "benign" ...)
    cleared = set()
    S = _sentences(body)
    for i, sent in enumerate(S):
        if _CLEARS.search(sent):  # the clearing sentence and the one before it ("... shows 1.2.3.4. These are not malicious")
            near = sent + " " + (S[i - 1] if i else "")
            cleared |= {v for (_k, v) in order if v in near}
    out = [found[k] for k in order if k[1] not in cleared or found[k]["strong"]]
    out.sort(key=lambda a: (not a["strong"], -a["n"], {"url": 0, "dns": 1, "ip": 2, "hash": 3}[a["kind"]]))
    return [{"kind": a["kind"], "value": a["value"], "strong": a["strong"]} for a in out if a["strong"] or a["n"] >= 2 or a["kind"] in ("ip", "hash", "url")][:limit]


# lookup / reputation / scanner sites: their pages list addresses, ranges and hashes of whatever was looked up - never IOCs
LOOKUP_SITES = {"ipinfo.io", "hash.cymru.com", "team-cymru.com", "pcrisk.com", "malwaretips.com", "virustotal.com", "abuseipdb.com",
                "urlscan.io", "shodan.io", "censys.io", "greynoise.io", "talosintelligence.com", "whois.com", "who.is", "ipvoid.com",
                "urlvoid.com", "scamadviser.com", "sitecheck.sucuri.net", "mxtoolbox.com", "robtex.com", "bgp.he.net", "spur.us",
                "threatminer.org", "otx.alienvault.com", "hybrid-analysis.com", "any.run", "joesandbox.com", "ipqualityscore.com",
                "cleantalk.org", "dnslytics.com", "securitytrails.com", "viewdns.info", "ip-api.com", "iplocation.net", "domaintools.com"}


def lookup_site(url):
    h = _host(url)
    return any(h == d or h.endswith("." + d) for d in LOOKUP_SITES)


def threat_like(title, snippet="", url=""):
    """A page / search result that reads like a threat report (worth reading in full for its indicators): judged on the title
    and search snippet only - a page body (an ipinfo or scanner page) mentions "threat" without being a report."""
    if url and lookup_site(url):
        return False
    return bool(THREAT_WORDS.search(f"{title} {snippet}"))
