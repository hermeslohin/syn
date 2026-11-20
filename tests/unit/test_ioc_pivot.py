"""Unit tests for research -> indicator hunt: iocs.extract, es_context.hunt, corr_llm._ioc_pivot / researched artifacts. (WEB-09)"""
import os, sys; sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__)))); import _env  # noqa: E402

import io  # noqa: E402
import json  # noqa: E402
import shutil  # noqa: E402
import subprocess  # noqa: E402
import unittest  # noqa: E402
from unittest import mock  # noqa: E402

import corr_llm  # noqa: E402
import es_context  # noqa: E402
import iocs  # noqa: E402

REPORT = """# Optimizely supply chain attack
![logo](https://cdn.publisher-cdn.com/logo.png) Read [the original](https://blog.report-uri.com/post/) on dope.security.
The loader pointed to `https://1688360.cc/track.js` and posted to card.php. Routers on 5vobauua3ojpklx[.]icu.
| Domain | Role |
| --- | --- |
| `webshell.lol` | injector |
C2 address 45.9.148.21, internal 10.0.0.5, hash `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.
Built with node.js; share on twitter.com.
"""


class Extract(unittest.TestCase):
    def test_report_indicators(self):
        """REQ: WEB-09"""
        got = {(a["kind"], a["value"]) for a in iocs.extract(REPORT, "https://dope.security/post/x", exclude=["cdn.optimizely.com"])}
        for want in [("url", "https://1688360.cc/track.js"), ("dns", "1688360.cc"), ("dns", "5vobauua3ojpklx.icu"), ("dns", "webshell.lol"),
                     ("ip", "45.9.148.21"), ("hash", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")]:
            self.assertIn(want, got)
        vals = {v for _k, v in got}
        for never in ("card.php", "node.js", "twitter.com", "dope.security", "10.0.0.5", "blog.report-uri.com", "cdn.publisher-cdn.com"):
            self.assertNotIn(never, vals)  # file names, platforms, the publisher, private IPs and link/image targets

    def test_markdown_defang_bare_paths_tlds_and_cleared(self):
        """REQ: WEB-09"""
        t = ("Served from cdn.optimizely\\[.\\]com loading 1688360\\[.\\]cc/track.js. In dope.console, block them.\n\n"
             "_DNS lookup for cdn.optimizely.com shows 104.18.65.57. These are delivery-resource associations, not malicious IP indicators._\n\n"
             "The C2 at 45.9.148.21 received the stolen cards.")
        vals = [a["value"] for a in iocs.extract(t, "", exclude=["cdn.optimizely.com"])]
        self.assertIn("https://1688360.cc/track.js", vals)
        self.assertIn("1688360.cc", vals)
        self.assertIn("45.9.148.21", vals)
        for never in ("cdn.optimizely", "cdn.optimizely.com", "dope.console", "104.18.65.57"):
            self.assertNotIn(never, vals)

    def test_lookup_pages_and_networks_are_never_indicators(self):
        """REQ: WEB-09 - an ipinfo / hash-lookup page is not a threat report, and a network address is not a host."""
        self.assertFalse(iocs.threat_like("2.59.21.51 IP address details", "", "https://ipinfo.io/2.59.21.51"))
        self.assertFalse(iocs.threat_like("Malware hash registry", "", "https://hash.cymru.com/docs_whois"))
        self.assertFalse(iocs.threat_like("2.59.21.51 IP address details", "page body: threat intelligence, abuse"[:0]))  # title only
        vals = [a["value"] for a in iocs.extract("C2 at `45.9.148.0` and `45.9.148.21`, range `104.0.0.0`", "")]
        self.assertEqual(vals, ["45.9.148.21"])

    def test_excluded_and_threat_like(self):
        """REQ: WEB-09"""
        self.assertEqual(iocs.extract("seen `cdn.optimizely.com` and `x.optimizely.com`", "", exclude=["cdn.optimizely.com"]), [])
        self.assertTrue(iocs.threat_like("Hackers hijack 178 websites", ""))
        self.assertFalse(iocs.threat_like("CDN recommendations - DXP docs", "configure caching"))


class Hunt(unittest.TestCase):
    def test_hunt_builds_one_bounded_aggregation(self):
        """REQ: WEB-09"""
        sent = {}

        def fake(req, context=None, timeout=None):
            sent["url"], sent["body"] = req.full_url, json.loads(req.data)
            return io.BytesIO(json.dumps({"aggregations": {"ioc": {"buckets": {
                "i0": {"doc_count": 3, "first": {"value_as_string": "2026-11-16T10:00:00Z"}, "last": {"value_as_string": "2026-11-16T11:00:00Z"},
                       "hosts": {"buckets": [{"key": "10.20.30.5", "doc_count": 3}]}, "logs": {"buckets": [{"key": "zeek.dns", "doc_count": 3}]},
                       "names": {"buckets": [{"key": "1688360.cc", "doc_count": 3}]}},
                "i1": {"doc_count": 0}}}}}).encode())
        with mock.patch.object(es_context.INTEG, "es_url", return_value="https://es"), mock.patch.object(es_context.INTEG, "es_key", return_value="k"), \
                mock.patch.object(es_context.urllib.request, "urlopen", fake):
            r = es_context.hunt([{"kind": "url", "value": "https://1688360.cc/track.js"}, {"kind": "ip", "value": "45.9.148.21"},
                                 {"kind": "ip", "value": "10.0.0.5"}, {"kind": "dns", "value": "bad value; DROP"}], days=99)
        self.assertEqual(r["days"], 30)  # capped
        self.assertEqual(r["results"]["https://1688360.cc/track.js"]["hits"], 3)
        self.assertEqual(r["results"]["https://1688360.cc/track.js"]["hosts"], [{"ip": "10.20.30.5", "count": 3}])
        self.assertEqual(r["results"]["45.9.148.21"]["hits"], 0)
        self.assertEqual(sorted(sent["body"]["aggs"]["ioc"]["filters"]["filters"]), ["i0", "i1"])  # private IP and junk never queried
        self.assertNotIn("script", json.dumps(sent["body"]))
        self.assertIn("dns.highest_registered_domain", json.dumps(sent["body"]))  # the attacker domain's sub-names count too


class Pivot(unittest.TestCase):
    def test_pivot_reads_report_hunts_and_stores_researched_artifacts(self):
        """REQ: WEB-09"""
        logw = corr_llm._web_logger("ti|dom|cdn.optimizely.com", [], "m", "unit-test")
        logw.rows = [("https://dope.security/post/x", "Optimizely supply chain attack: 178 brands served malware", "s"),
                     ("https://docs.optimizely.com/cdn", "CDN recommendations", "docs")]
        logw.seen.update({u: t for u, t, _s in logw.rows})
        for u, _t, _s in logw.rows:
            corr_llm._web_id(logw, u)
        fetched = []

        def fetch(url, chars=8000, cfg=None):
            fetched.append(url)
            return {"url": url, "title": "report", "text": REPORT}

        def brk(path, body=None, timeout=330):
            self.assertEqual(path, "/iochunt")
            return {"days": 30, "checked": "now", "results": {"1688360.cc": {"hits": 2, "hosts": [{"ip": "10.20.30.5", "count": 2}], "first": "a", "last": "b", "logs": ["zeek.dns"]}}}
        import webtools
        anchor = {"label": "looked up cdn.optimizely.com - listed in opencti_hosts", "arts": [], "ips": []}
        with mock.patch.object(webtools, "fetch", fetch), mock.patch.object(corr_llm, "broker", brk), mock.patch.object(corr_llm, "_web_cache", return_value=None):
            out = corr_llm._ioc_pivot(logw, anchor)
            self.assertEqual(corr_llm._ioc_pivot(logw, anchor), [])  # each report is read and hunted once per review
        self.assertEqual(fetched, ["https://dope.security/post/x"])  # only the threat report, not the vendor docs
        self.assertEqual(len(out), 1)
        self.assertIn("<ioc_hunt", out[0])
        self.assertIn("dns 1688360.cc (from [W1]): SEEN HERE 2x", out[0])
        self.assertIn("not seen in this network's logs", out[0])
        vals = [a["value"] for a in logw.iocs]
        self.assertIn("https://1688360.cc/track.js", vals)
        self.assertNotIn("cdn.optimizely.com", vals)  # the event's own indicator is not new research
        with corr_llm._db() as c:
            corr_llm.save_event_iocs(c, "ti|dom|cdn.optimizely.com", logw.iocs, "m")
            c.execute("INSERT OR REPLACE INTO event_class (eid, label, confidence, reason, model, sig, ts) VALUES (?,?,?,?,?,?,?)",
                      ("ti|dom|cdn.optimizely.com", "suspicious", 0.8, "r", "m", "s", 1.0))
        got = corr_llm.classes(["ti|dom|cdn.optimizely.com"])["ti|dom|cdn.optimizely.com"]["iocs"]
        hit = next(a for a in got if a["value"] == "1688360.cc")
        self.assertEqual((hit["wid"], hit["hunt"]["hits"], hit["src_url"]), ("W1", 2, "https://dope.security/post/x"))

    def test_indicators_get_bad_artifact_notes_with_the_report(self):
        """REQ: WEB-09 - each researched indicator gets an artifact note: malicious, with the article(s) naming it."""
        import kb
        iocs_ = [{"kind": "url", "value": "https://loader-example.cc/track.js", "src_url": "https://r.example/a", "src_title": "Vendor hijacked",
                  "hunt": {"hits": 0, "days": 30, "checked": "2026-11-20T01:00:00"}},
                 {"kind": "ip", "value": "203.0.113.40", "src_url": "https://r.example/a", "hunt": {"hits": 2, "days": 30, "last": "b", "hosts": [{"ip": "10.20.30.5", "count": 2}]}},
                 {"kind": "dns", "value": "not a domain", "src_url": "https://r.example/a"}]
        self.assertEqual(kb.add_ioc_notes(iocs_, "m", "event reviewer"), 2)
        d = kb.host_notes(["art:dns:loader-example.cc"])
        self.assertEqual(len(d), 1)
        self.assertTrue(d[0]["text"].startswith("[ioc:dns:loader-example.cc] MALICIOUS"))
        self.assertIn("https://r.example/a", d[0]["text"])
        self.assertIn("URL in the report: https://loader-example.cc/track.js.", d[0]["text"])
        self.assertIn("Not seen on this network", d[0]["text"])
        self.assertEqual((d[0]["category"], d[0]["author"]), ("risk", "ai"))
        self.assertIn("SEEN on this network: 2x", kb.host_notes(["art:ip:203.0.113.40"])[0]["text"])
        # a second report naming it: same note, both links
        kb.add_ioc_notes([{"kind": "dns", "value": "loader-example.cc", "src_url": "https://r2.example/b"}], "m")
        d = kb.host_notes(["art:dns:loader-example.cc"])
        self.assertEqual(len(d), 1)
        self.assertIn("https://r2.example/b", d[0]["text"])
        self.assertIn("https://r.example/a", d[0]["text"])
        # a person's verdict on the note is never overwritten by the AI
        kb.review_host_note(d[0]["id"], "reject", "alice")
        kb.add_ioc_notes([{"kind": "dns", "value": "loader-example.cc", "src_url": "https://r3.example/c"}], "m")
        self.assertNotIn("r3.example", kb.host_notes(["art:dns:loader-example.cc"])[0]["text"])

    def test_non_threat_pages_are_not_mined(self):
        """REQ: WEB-09 - a vendor docs page the reviewer read does not get its domains labelled malicious."""
        logw = corr_llm._web_logger("x", [], "m", "unit-test")
        logw.seen["https://docs.vendor.example/cdn"] = "CDN recommendations"
        logw.pages = {"https://docs.vendor.example/cdn": "Point `edge.partner-cdn.net` at the origin. Use `edge.partner-cdn.net` for assets."}
        with mock.patch.object(corr_llm, "broker", side_effect=AssertionError("no hunt")):
            self.assertEqual(corr_llm._ioc_pivot(logw, {"label": "x"}), [])

    def test_hunt_failure_still_lists_indicators(self):
        """REQ: WEB-09"""
        logw = corr_llm._web_logger("x", [], "m", "unit-test")
        logw.pages = {"https://r.example/a": "C2 `evil-c2.top` used"}
        logw.seen["https://r.example/a"] = "Campaign report: new C2 infrastructure"

        def brk(*a, **k):
            raise RuntimeError("broker down")
        with mock.patch.object(corr_llm, "broker", brk), mock.patch.object(corr_llm, "IOC_HUNT_TTL", 0):
            out = corr_llm._ioc_pivot(logw, {"label": "x"})
        self.assertIn("log search failed", out[0])


NODE_FALLBACK = os.path.expanduser(os.environ.get("NETMON_NODE", "~/.hermes/tools/node-26.7.0-linux-arm64/bin/node"))
NODE = shutil.which("node") or (NODE_FALLBACK if os.path.exists(NODE_FALLBACK) else None)


@unittest.skipUnless(NODE, "node not available")
class Ui(unittest.TestCase):
    def test_researched_artifact_tag_and_escaping(self):
        """REQ: WEB-09"""
        here = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        js = r"""
const fs = require('fs'); const s = fs.readFileSync(process.argv[1], 'utf8');
const grab = (n) => { const i = s.indexOf('function ' + n + '('); let d = 0, j = s.indexOf('{', i); for (let k = j; k < s.length; k++) { if (s[k] == '{') d++; else if (s[k] == '}' && --d == 0) return s.slice(i, k + 1); } };
const esc = (x) => String(x).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
const safeUrl = (u) => /^https?:\/\//i.test(String(u || '')) ? u : ''; const ft = (t) => t; const aiFlare = () => '';
const ART_ICON = { dns: 'D', ip: 'I' }; const window = {};
eval(grab('iocsHtml'));
process.stdout.write(iocsHtml([{ kind: 'dns', value: '1688360.cc<img>', wid: 'W1', src_url: 'https://r.example/a', hunt: { hits: 0, days: 30 } },
  { kind: 'url', value: 'https://evil.top/x.js', src_url: 'javascript:alert(1)', hunt: { hits: 2, days: 30, hosts: [{ ip: '10.20.30.5', count: 2 }], last: 'b' } }], []));
"""
        out = subprocess.run([NODE, "-e", js, os.path.join(here, "dashboard", "app", "static", "related.js")],  # noqa: S603 - node on a repo file, fixed script
                             capture_output=True, text=True, check=True, timeout=30).stdout
        self.assertEqual(out.count("🔬 researched artifact"), 2)
        self.assertIn("not seen here in 30 days", out)
        self.assertIn("seen here 2× in 30 days", out)
        self.assertIn("1 seen in this network", out)
        self.assertNotIn("<img>", out)
        self.assertNotIn("javascript:", out)


if __name__ == "__main__":
    unittest.main()
