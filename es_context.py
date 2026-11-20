#!/usr/bin/python3
"""Read-only Elasticsearch look-ups for the event reviewer (host_broker.py POST /esquery).

The event reviewer model may ask for extra context before it decides a link (AI pipeline configuration > Models > "Elasticsearch
queries"). It never sends Elasticsearch DSL: it sends a small structured request, this module validates it and
builds the query itself, so the model can only run bounded `_search` requests on the Security Onion indices.

  {"source": "zeek" | "suricata" | "detections" | "endpoint" | "auth",
   "match":  {"<field>": "<value>" | [values], ...}     up to 6 exact (term/terms) filters
   "text":   "<simple_query_string>"                     optional, 200 chars, no leading wildcards
   "start":  ISO time, "end": ISO time                   default: anchor time -2 h .. +2 h; span <= 7 days
   "group_by": "<field>"                                 optional: top 10 values with counts instead of documents
   "size":   1..10                                       documents returned (default 5)
   "why":    "<one line: what the model wants to learn>"}

Results are trimmed (selected flat fields, 400 chars per document) and returned as data; the caller wraps them
in <es_result> tags and the event reviewer's system prompt says never to follow instructions inside them.
CLI: es_context.py '<request json>' [anchor_epoch]
"""
import json, os, re, ssl, sys, urllib.request
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import integrations as INTEG  # noqa: E402

SOURCES = {  # name -> (index pattern, what it holds) - shown to the model
    "zeek": ("logs-zeek-so", "Zeek network logs: conn, dns, ssl, http, ssh, rdp, smb, ntlm, kerberos, notice, dhcp (event.dataset tells which)"),
    "suricata": ("logs-suricata.alerts-so", "Suricata IDS alerts (rule.name, rule.category)"),
    "detections": ("logs-detections.alerts-so", "Security Onion detection rule hits (rule.name)"),
    "endpoint": ("logs-endpoint.events.*", "Elastic Agent endpoint events: process, network, file (host.name, process.*, user.name)"),
    "auth": ("logs-system.auth-*", "Linux auth logs from Elastic Agent (sshd/sudo: event.outcome, user.name, source.ip)"),
}
FIELD = re.compile(r"^[A-Za-z0-9_@][A-Za-z0-9_.@-]{0,80}$")
KEEP = ("@timestamp", "event.dataset", "event.action", "event.outcome", "source.ip", "source.port", "destination.ip",
        "destination.port", "network.transport", "network.protocol", "connection.state", "rule.name", "rule.category",
        "dns.query.name", "dns.answers.name", "ssl.server_name", "tls.client.server_name", "http.request.method",
        "url.original", "http.virtual_host", "user.name", "host.name", "process.name", "process.command_line",
        "process.parent.name", "file.path", "ssh.auth_success", "client.bytes", "server.bytes", "message")
MAX_SPAN = timedelta(days=7)
DOC_CHARS, TEXT_CHARS = 400, 200


def _flat(d, p=""):
    for k, v in (d or {}).items():
        key = f"{p}{k}"
        if isinstance(v, dict):
            yield from _flat(v, key + ".")
        else:
            yield key, v


def _t(v, default):
    if not v:
        return default
    s = str(v).strip().replace("Z", "+00:00")
    try:
        t = datetime.fromisoformat(s)
    except ValueError:
        raise ValueError(f"bad time {str(v)[:40]!r} (use ISO 8601, UTC)") from None
    return t if t.tzinfo else t.replace(tzinfo=timezone.utc)


def build(req, anchor=None):
    """Validate the model's request -> (index, ES body, normalised request). Raises ValueError on anything odd."""
    if not isinstance(req, dict):
        raise ValueError("query must be an object")
    src = str(req.get("source") or "")
    if src not in SOURCES:
        raise ValueError(f"source must be one of {', '.join(SOURCES)}")
    now = datetime.now(timezone.utc)
    a = datetime.fromtimestamp(float(anchor), timezone.utc) if anchor else now
    start, end = _t(req.get("start"), a - timedelta(hours=2)), _t(req.get("end"), min(now, a + timedelta(hours=2)))
    if end <= start:
        raise ValueError("end must be after start")
    if end - start > MAX_SPAN:
        start = end - MAX_SPAN
    filt: list = [{"range": {"@timestamp": {"gte": start.isoformat(), "lte": end.isoformat()}}}]
    match = req.get("match") or {}
    if not isinstance(match, dict) or len(match) > 6:
        raise ValueError("match: an object with at most 6 fields")
    for f, v in match.items():
        if not FIELD.match(str(f)):
            raise ValueError(f"bad field name {str(f)[:40]!r}")
        vals = v if isinstance(v, list) else [v]
        vals = [x for x in vals if isinstance(x, (str, int, float, bool))][:20]
        if not vals:
            raise ValueError(f"match.{f}: give a value or a list of values")
        vals = [str(x)[:200] if isinstance(x, str) else x for x in vals]
        filt.append({"terms": {f: vals}} if len(vals) > 1 else {"term": {f: vals[0]}})
    must = []
    text = str(req.get("text") or "").strip()[:TEXT_CHARS]
    if text:
        if re.search(r"(^|\s)[*?]", text):
            raise ValueError("text: no leading wildcards")
        must.append({"simple_query_string": {"query": text, "default_operator": "and", "lenient": True,
                                             "flags": "AND|OR|NOT|PHRASE|PREFIX|PRECEDENCE|ESCAPE|WHITESPACE"}})
    body = {"query": {"bool": {"filter": filt, "must": must}}, "track_total_hits": 100000, "timeout": "20s",
            "sort": [{"@timestamp": "desc"}]}
    gb = str(req.get("group_by") or "")
    if gb:
        if not FIELD.match(gb):
            raise ValueError("bad group_by field")
        body.update(size=0, aggs={"top": {"terms": {"field": gb, "size": 10}}})
        body.pop("sort")
    else:
        body["size"] = max(1, min(int(req.get("size") or 5), 10))
        body["_source"] = list(KEEP)
    norm = {"source": src, "match": match, "text": text, "start": start.isoformat(timespec="seconds"),
            "end": end.isoformat(timespec="seconds"), "group_by": gb, "size": body.get("size", 0), "why": str(req.get("why") or "")[:200]}
    index = INTEG.map_index(SOURCES[src][0])
    norm["es_index"] = index  # lets the dashboard turn the search into a Kibana Discover link (esk.py)
    return index, body, norm


def run(req, anchor=None):
    index, body, norm = build(req, anchor)
    url, key = INTEG.es_url(), INTEG.es_key()
    if not (url and key):
        raise ValueError("Elasticsearch is not configured (Configuration > Integrations)")
    r = urllib.request.Request(f"{url}/{index}/_search", data=json.dumps(body).encode(),  # noqa: S310 - https ES URL from settings
                               headers={"Authorization": f"ApiKey {key}", "Content-Type": "application/json"})
    # Security Onion's ES uses its own CA (same as collect.py)
    d = json.load(urllib.request.urlopen(r, context=ssl._create_unverified_context(), timeout=30))  # noqa: S310, S323
    total = (d.get("hits") or {}).get("total") or {}
    out = {"query": norm, "total": total.get("value", 0) if isinstance(total, dict) else total}
    if norm["group_by"]:
        out["top"] = [{"value": b.get("key_as_string", b.get("key")), "count": b.get("doc_count")}
                      for b in (d.get("aggregations") or {}).get("top", {}).get("buckets", [])]
    else:
        docs = []
        for h in d["hits"]["hits"]:
            src = dict(_flat(h.get("_source")))
            flat = {k: src[k] for k in KEEP if src.get(k) not in (None, "", [])}  # fixed order: time and 5-tuple first
            if "message" in flat:  # Zeek's message is the raw JSON log line (duplicates the fields): drop it
                m = str(flat.pop("message"))
                if not m.lstrip().startswith("{"):
                    flat["message"] = m[:150]
            docs.append(json.dumps(flat, default=str, separators=(",", ":"))[:DOC_CHARS])
        out["docs"] = docs
    return out


HUNT_DAYS = 30
_HFIELDS = {"dns": ("dns.query.name", "dns.highest_registered_domain", "ssl.server_name", "tls.client.server_name", "http.virtual_host",
                    "url.domain", "destination.domain"),
            "ip": ("destination.ip", "source.ip"),
            "hash": ("hash.md5", "hash.sha1", "hash.sha256", "file.hash.md5", "file.hash.sha1", "file.hash.sha256",
                     "process.hash.md5", "process.hash.sha1", "process.hash.sha256")}


def hunt(iocs, days=HUNT_DAYS):
    """Has this network ever touched these indicators? One aggregation over the Zeek, Suricata and endpoint logs of the
    last `days` (<= 30): per indicator its hit count, first / last time, the busiest local hosts and the log types.
    iocs = [{"kind": "dns" | "url" | "ip" | "hash", "value"}] (validated here; at most 20) -> {value: {...}}.
    The DSL is built here from the validated values only (read-only _search, no scripts)."""
    import ipaddress
    days = max(1, min(int(days or HUNT_DAYS), 30))
    flt, keys = {}, {}
    for a in (iocs or [])[:20]:
        kind, v = str((a or {}).get("kind") or ""), str((a or {}).get("value") or "").strip()
        if kind == "url":
            m = re.match(r"(?:https?|ftp)://([^/:?#]+)", v, re.I)
            kind, v = "dns", (m.group(1) if m else "")
        v = v.lower()
        if kind == "dns" and re.fullmatch(r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,23}", v) and len(v) <= 253:
            p = v.split(".")
            rd = ".".join(p[-3:] if len(p) >= 3 and len(p[-1]) == 2 and p[-2] in ("co", "com", "net", "org", "gov", "edu", "ac") else p[-2:])
            should = [{"term": {f: v}} for f in _HFIELDS["dns"]]
            if rd == v:  # the attacker's own registered domain: every sub-name counts too
                should.append({"term": {"dns.highest_registered_domain": rd}})
        elif kind == "ip":
            try:
                if not ipaddress.ip_address(v).is_global:
                    continue
            except ValueError:
                continue
            should = [{"term": {f: v}} for f in _HFIELDS["ip"]]
        elif kind == "hash" and re.fullmatch(r"[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64}", v):
            should = [{"term": {f: v}} for f in _HFIELDS["hash"]]
        else:
            continue
        k = f"i{len(flt)}"
        flt[k], keys[k] = {"bool": {"should": should, "minimum_should_match": 1}}, (a.get("kind"), str(a.get("value")))
    if not flt:
        return {"days": days, "results": {}}
    url, key = INTEG.es_url(), INTEG.es_key()
    if not (url and key):
        raise ValueError("Elasticsearch is not configured (Configuration > Integrations)")
    now = datetime.now(timezone.utc)
    body = {"size": 0, "timeout": "30s", "query": {"bool": {"filter": [{"range": {"@timestamp": {"gte": (now - timedelta(days=days)).isoformat(),
                                                                                                   "lte": now.isoformat()}}}],
                                                         "should": list(flt.values()), "minimum_should_match": 1}},
            "aggs": {"ioc": {"filters": {"filters": flt}, "aggs": {
                "first": {"min": {"field": "@timestamp"}}, "last": {"max": {"field": "@timestamp"}},
                "hosts": {"terms": {"field": "source.ip", "size": 5}}, "logs": {"terms": {"field": "event.dataset", "size": 6}},
                "names": {"terms": {"field": "dns.query.name", "size": 5}}}}}}
    index = ",".join(INTEG.map_index(SOURCES[s][0]) for s in ("zeek", "suricata", "endpoint"))
    r = urllib.request.Request(f"{url}/{index}/_search?ignore_unavailable=true&allow_no_indices=true", data=json.dumps(body).encode(),  # noqa: S310
                               headers={"Authorization": f"ApiKey {key}", "Content-Type": "application/json"})
    d = json.load(urllib.request.urlopen(r, context=ssl._create_unverified_context(), timeout=45))  # noqa: S310, S323
    out = {}
    for k, b in ((d.get("aggregations") or {}).get("ioc") or {}).get("buckets", {}).items():
        if k not in keys:
            continue
        n = int(b.get("doc_count") or 0)
        out[keys[k][1]] = {"kind": keys[k][0], "hits": n,
                           "first": (b.get("first") or {}).get("value_as_string") if n else None,
                           "last": (b.get("last") or {}).get("value_as_string") if n else None,
                           "hosts": [{"ip": x["key"], "count": x["doc_count"]} for x in (b.get("hosts") or {}).get("buckets", [])],
                           "logs": [x["key"] for x in (b.get("logs") or {}).get("buckets", [])],
                           "names": [x["key"] for x in (b.get("names") or {}).get("buckets", [])]}
    return {"days": days, "results": out, "checked": now.isoformat(timespec="seconds")}


def describe():
    """The query help text placed in the event reviewer's system prompt."""
    return "\n".join(f"  - {k}: {v[1]}" for k, v in SOURCES.items())


if __name__ == "__main__":
    print(json.dumps(run(json.loads(sys.argv[1]), float(sys.argv[2]) if len(sys.argv) > 2 else None), indent=1))
