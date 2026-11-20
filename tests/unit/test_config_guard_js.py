"""config.js (Settings > Configuration > Auto-close) under node with a stubbed page: the guard rails save on every change
(no separate Save button), and every save carries the switches and the guard rails as shown, so a switch tap never
discards an unsaved guard-rail edit and a pending guard-rail save never undoes a switch."""
import os, sys; sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__)))); import _env  # noqa: E401,E402

import json  # noqa: E402
import shutil  # noqa: E402
import subprocess  # noqa: E402
import unittest  # noqa: E402

NODE_FALLBACK = os.path.expanduser(os.environ.get("NETMON_NODE", "~/.hermes/tools/node-26.7.0-linux-arm64/bin/node"))
NODE = shutil.which("node") or (NODE_FALLBACK if os.path.exists(NODE_FALLBACK) else None)
CFG_JS = os.path.join(_env.APP, "static", "config.js")

# A fake page: card() returns an element whose querySelector(All) hand out stub inputs (value / checked / dataset /
# onchange), so the test can play a person's taps and see every POST the page sends.
HARNESS = r"""
const fs = require("fs"), vm = require("vm");
const [src, scenario] = process.argv.slice(2);
const D = { admin: true, settings: { reviewer_expected: false, reviewer_benign: true, researcher_expected: false, researcher_benign: false,
  min_conf: 0.8, expire_days: 7, host_hold: true, protect: ["admin"] },
  categories: { admin: "Admin", c2_exfil: "C2", exposure: "Exposure" }, guard: {}, review: {} };
const posts = [];
const mk = (props) => ({ value: "", checked: false, dataset: {}, onchange: null, onclick: null, className: "", textContent: "", style: {}, ...props });
function makeCard() {
  const els = {
    "#g-conf": mk({ value: String(D.settings.min_conf) }), "#g-exp": mk({ value: String(D.settings.expire_days) }),
    "#g-hold": mk({ checked: D.settings.host_hold }), "#g-msg": mk({}),
  };
  const cats = Object.keys(D.categories).map((k) => mk({ dataset: { k }, checked: D.settings.protect.includes(k) }));
  const sw = ["reviewer_expected", "reviewer_benign", "researcher_expected", "researcher_benign"].map((k) => mk({ dataset: { k }, checked: !!D.settings[k] }));
  const c = { id: "", style: {}, els, cats, sw,
    querySelector(s) {
      if (els[s]) return els[s];
      const m = s.match(/^\.cfg-ac\[data-k="(\w+)"\]$/); if (m) return sw.find((x) => x.dataset.k === m[1]) || null;
      return null; },
    querySelectorAll(s) {
      if (s === ".cfg-ac") return sw; if (s === ".g-cat") return cats; if (s === ".g-cat:checked") return cats.filter((x) => x.checked);
      if (s === "#g-conf, #g-exp, #g-hold, .g-cat") return [els["#g-conf"], els["#g-exp"], els["#g-hold"], ...cats];
      return []; } };
  return c;
}
let cur = null;
const tri = { querySelector: () => null, appendChild(c) { if (c && c.els) cur = c; }, insertAdjacentHTML() {}, after() {}, set innerHTML(v) {} };
const el = { innerHTML: "", querySelector: () => ({ remove() {} }), append() {} };
const timers = [];
const ctx = { console, JSON, Math, Object, Array, Set, Map, String, Number, Promise, parseFloat, parseInt,
  S: {}, V: {}, esc: (s) => String(s ?? ""), ft: (v) => String(v), alert: (m) => posts.push({ alert: String(m) }), confirm: () => true,
  card: () => makeCard(), api: async (u) => (u === "/api/config/triage" ? D : u === "/api/acks" ? {} : { _err: "n/a" }),
  apiPost: async (u, b) => { posts.push({ url: u, body: b }); Object.assign(D.settings, b); return D; },
  setTimeout: (f, ms) => { timers.push(f); return timers.length; }, clearTimeout: (i) => { if (i) timers[i - 1] = null; },
  document: { createElement: () => ({ ...tri }), querySelector: () => null } };
ctx.window = ctx; ctx.window.suppressRulesCard = () => ({});
vm.createContext(ctx);
vm.runInContext(fs.readFileSync(src, "utf8"), ctx);
const flush = async () => { for (let i = 0; i < 5; i++) await new Promise((r) => setImmediate(r)); };
const fire = () => { const t = timers.splice(0); t.forEach((f) => f && f()); };
(async () => {
  const root = { ...el, append(a) { a.querySelector = () => null; } };
  // V.config builds two wrappers with document.createElement; the auto-close card lands in cur via appendChild
  await ctx.V.config(root);
  const c = () => cur;
  if (!c()) throw new Error("auto-close card not painted");
  const out = { hasSaveButton: !!c().querySelector("#g-save") };
  if (scenario === "guard") {           // tick a category: one save with every guard-rail value and the switches as shown
    const cat = c().cats.find((x) => x.dataset.k === "c2_exfil"); cat.checked = true; cat.onchange();
    out.beforeTimer = posts.length; fire(); await flush();
  } else if (scenario === "edit-then-switch") {   // type days, then tap a switch before the guard save fires
    c().els["#g-exp"].value = "21"; c().els["#g-exp"].onchange();
    const s = c().sw.find((x) => x.dataset.k === "reviewer_expected"); s.checked = true; s.onchange(); await flush();
    fire(); await flush();
  } else if (scenario === "bad") {
    c().els["#g-conf"].value = "3"; c().els["#g-conf"].onchange(); fire(); await flush();
    out.msg = c().els["#g-msg"].textContent;
  }
  out.posts = posts; out.msgAfter = c().els["#g-msg"].textContent;
  process.stdout.write(JSON.stringify(out));
})().catch((e) => { console.error(e && e.stack || e); process.exit(1); });
"""


@unittest.skipUnless(NODE, "node not available")
class GuardRailsSaveTest(unittest.TestCase):
    def run_js(self, scenario):
        d = os.environ["NETMON_TEST_TMP"]
        hp = os.path.join(d, "cfg_guard_harness.js")
        with open(hp, "w") as f:
            f.write(HARNESS)
        r = subprocess.run([NODE, hp, CFG_JS, scenario], capture_output=True, text=True, timeout=30)  # noqa: S603 - node on repo files
        self.assertEqual(r.returncode, 0, r.stderr)
        return json.loads(r.stdout)

    def test_guard_rail_change_saves_at_once(self):
        """Ticking a protected category saves it (after a short debounce) with every guard-rail value and the switches;
        there is no separate Save button to forget, and the card says Saved.
        REQ: SET-64
        """
        out = self.run_js("guard")
        self.assertFalse(out["hasSaveButton"])
        self.assertEqual(out["beforeTimer"], 0)
        (p,) = out["posts"]
        self.assertEqual(p["url"], "/api/config/triage")
        self.assertEqual(sorted(p["body"]["protect"]), ["admin", "c2_exfil"])
        self.assertEqual((p["body"]["min_conf"], p["body"]["expire_days"], p["body"]["host_hold"], p["body"]["reviewer_benign"]), (0.8, 7, True, True))
        self.assertIn("Saved", out["msgAfter"])

    def test_switch_tap_keeps_pending_guard_edit(self):
        """Typing a guard-rail value and then tapping an auto-close switch sends ONE save holding both; the pending
        guard-rail save is folded in, so it can neither be lost nor undo the switch.
        REQ: SET-64
        """
        out = self.run_js("edit-then-switch")
        (p,) = out["posts"]
        self.assertEqual((p["body"]["expire_days"], p["body"]["reviewer_expected"], p["body"]["reviewer_benign"]), (21, True, True))

    def test_out_of_range_value_is_not_saved(self):
        """An out-of-range confidence is not sent; the card says why.
        REQ: SET-64
        """
        out = self.run_js("bad")
        self.assertEqual(out["posts"], [])
        self.assertIn("Not saved", out["msg"])


if __name__ == "__main__":
    unittest.main()
