"""Token use of the AI pipeline's background steps, per hour: the decision model (clef, correlation), the event reviewer
(event-review / event-classify / correlation-review calls) and the other calls that share its model (owner advice,
note consolidation). Drawn on AI pipeline monitoring > "Tokens: correlation and event reviewer" as a stacked bar chart,
with an estimated cost line when the admin entered prices for the model (llm_providers.price, read when the chart loads,
so prices entered later apply to the whole history).

Storage: table ai_usage in corr_llm.db, one row per (hour, step, provider, model). Calls are summed in memory and
written at most every FLUSH_S seconds (the decision model makes thousands of calls a day) and at exit.
History from before this table existed is filled once from the audit log (Elasticsearch netmon.llm entries), see backfill().
"""
import atexit
import os
import sqlite3
import sys
import threading
import time

DB = os.path.join(os.environ.get("STATE_DIR", "/state"), "corr_llm.db")
FLUSH_S = 30
KEEP_DAYS = 400
# step key -> chart series; purposes of corr_llm._complete map onto these
STEPS = {"correlation": "Correlation (decision model)", "event-review": "Event reviewer",
         "advice": "Owner advice (event reviewer model)", "notes": "Note consolidation (event reviewer model)"}
PURPOSE_STEP = {"event-review": "event-review", "event-classify": "event-review", "correlation-review": "event-review",
                "user-advice": "advice", "notes-consolidation": "notes"}

_lock = threading.Lock()
_buf = {}
_last = [time.time()]
_schema_done = [False]


def _db():
    c = sqlite3.connect(DB, timeout=10)
    c.execute("PRAGMA temp_store=MEMORY")  # read-only container: sorts must not spill to temp files
    if not _schema_done[0]:
        c.execute("""CREATE TABLE IF NOT EXISTS ai_usage (hour INTEGER, step TEXT, provider TEXT, model TEXT, prompt INTEGER,
                     completion INTEGER, cache_read INTEGER, calls INTEGER, PRIMARY KEY (hour, step, provider, model))""")
        c.execute("CREATE TABLE IF NOT EXISTS ai_usage_meta (k TEXT PRIMARY KEY, v REAL)")
        c.execute("INSERT OR IGNORE INTO ai_usage_meta (k, v) VALUES ('live_since', ?)", (time.time(),))
        c.commit()
        _schema_done[0] = True
    return c


def step_of(purpose):
    return PURPOSE_STEP.get(str(purpose or ""))


def record(step, provider, model, prompt=0, completion=0, cache_read=0, calls=1):
    """Add one call's tokens to the hour bucket (never raises: usage accounting must not break a review)."""
    if step not in STEPS:
        return
    try:
        k = (int(time.time() // 3600 * 3600), step, str(provider or ""), str(model or ""))
        with _lock:
            b = _buf.setdefault(k, [0, 0, 0, 0])
            b[0] += int(prompt or 0)
            b[1] += int(completion or 0)
            b[2] += int(cache_read or 0)
            b[3] += int(calls or 0)
            due = time.time() - _last[0] >= FLUSH_S
        if due:
            flush()
    except Exception as e:  # noqa: BLE001
        print(f"aiusage: record failed: {e}", file=sys.stderr)


def flush():
    with _lock:
        rows = [(*k, *v) for k, v in _buf.items()]
        _buf.clear()
        _last[0] = time.time()
    if not rows:
        return
    try:
        with _db() as c:
            c.executemany("""INSERT INTO ai_usage (hour, step, provider, model, prompt, completion, cache_read, calls) VALUES (?,?,?,?,?,?,?,?)
                             ON CONFLICT (hour, step, provider, model) DO UPDATE SET prompt = prompt + excluded.prompt,
                             completion = completion + excluded.completion, cache_read = cache_read + excluded.cache_read,
                             calls = calls + excluded.calls""", rows)
            c.execute("DELETE FROM ai_usage WHERE hour < ?", (time.time() - KEEP_DAYS * 86400,))
    except Exception as e:  # noqa: BLE001
        print(f"aiusage: flush failed: {e}", file=sys.stderr)


atexit.register(flush)


def backfill():
    """Once: hourly token sums per purpose / provider / model from the audit log, for the time before live recording
    started (the decision model was never audit-logged, so its history starts with live recording)."""
    try:
        with _db() as c:
            if c.execute("SELECT v FROM ai_usage_meta WHERE k='backfilled'").fetchone():
                return 0
            since = c.execute("SELECT v FROM ai_usage_meta WHERE k='live_since'").fetchone()[0]
        import audit
        body = {"size": 0, "query": {"bool": {"filter": [{"term": {"event.dataset": "netmon.llm"}},
                                                          {"terms": {"event.action": ["llm." + p for p in PURPOSE_STEP]}},
                                                          {"range": {"@timestamp": {"gte": f"now-{KEEP_DAYS}d", "lt": int(since * 1000), "format": "epoch_millis"}}}]}},
                "aggs": {"h": {"date_histogram": {"field": "@timestamp", "fixed_interval": "1h", "min_doc_count": 1},
                               "aggs": {"k": {"multi_terms": {"terms": [{"field": "event.action"}, {"field": "gen_ai.system", "missing": ""},
                                                                        {"field": "gen_ai.request.model", "missing": ""}], "size": 50},
                                              "aggs": {"i": {"sum": {"field": "gen_ai.usage.input_tokens"}},
                                                       "o": {"sum": {"field": "gen_ai.usage.output_tokens"}}}}}}}}
        r = audit._es("POST", f"/{audit.read_pattern()}/_search?{audit.RQ}", body, timeout=60)
        rows = []
        for h in ((r.get("aggregations") or {}).get("h") or {}).get("buckets", []):
            for b in h["k"]["buckets"]:
                act, prov, model = b["key"]
                st = step_of(str(act).removeprefix("llm."))
                if st:
                    rows.append((int(h["key"] // 1000), st, prov, model, int(b["i"]["value"]), int(b["o"]["value"]), 0, b["doc_count"]))
        with _db() as c:
            c.executemany("""INSERT INTO ai_usage (hour, step, provider, model, prompt, completion, cache_read, calls) VALUES (?,?,?,?,?,?,?,?)
                             ON CONFLICT (hour, step, provider, model) DO UPDATE SET prompt = prompt + excluded.prompt,
                             completion = completion + excluded.completion, calls = calls + excluded.calls""", rows)
            c.execute("INSERT OR REPLACE INTO ai_usage_meta (k, v) VALUES ('backfilled', ?)", (time.time(),))
        return len(rows)
    except Exception as e:  # noqa: BLE001 - Elasticsearch down / audit off: try again on the next start
        print(f"aiusage: backfill skipped: {e}", file=sys.stderr)
        return -1


def view(days=30, tz_min=0):
    """Chart data: buckets (hourly for 1-2 days, else daily, in the browser's time zone: tz_min = minutes east of UTC) x step tokens, plus est. cost per
    bucket when any of the models has a price."""
    import llm_providers as LP
    flush()
    days = max(1, min(int(days), KEEP_DAYS))
    off = max(-14 * 60, min(int(tz_min), 14 * 60)) * 60
    hourly = days <= 2
    now = time.time()
    with _db() as c:
        rows = c.execute("SELECT hour, step, provider, model, prompt, completion, cache_read, calls FROM ai_usage WHERE hour >= ? ORDER BY hour",
                         (now - days * 86400,)).fetchall()
        live = (c.execute("SELECT v FROM ai_usage_meta WHERE k='live_since'").fetchone() or [None])[0]
    prices, models = {}, {}
    out, order = {}, []
    for hour, st, prov, model, pi, po, cr, n in rows:
        lt = time.gmtime(hour + off)
        key = time.strftime("%Y-%m-%d %H:00" if hourly else "%Y-%m-%d", lt)
        b = out.get(key)
        if b is None:
            b = out[key] = {"t": key, "tokens": {}, "prompt": {}, "completion": {}, "calls": {}, "cost": {}}
            order.append(key)
        for f, v in (("tokens", pi + po), ("prompt", pi), ("completion", po), ("calls", n)):
            b[f][st] = b[f].get(st, 0) + v
        if (prov, model) not in prices:
            try:
                prices[(prov, model)] = LP.price(prov, model) if prov and model and st != "correlation" else None
            except Exception:  # noqa: BLE001
                prices[(prov, model)] = None
        models.setdefault(st, set()).add(model)
        pr = prices[(prov, model)]
        if pr is not None:
            usd = (max(0, pi - cr) * pr["in"] + cr * pr["cache_read"] + po * pr["out"]) / 1e6
            b["cost"][st] = b["cost"].get(st, 0.0) + usd
    priced = any(p and (p["in"] or p["out"]) for p in prices.values())
    return {"buckets": [out[k] for k in order], "hourly": hourly, "days": days, "steps": STEPS, "priced": priced,
            "models": {k: sorted(m for m in v if m) for k, v in models.items()}, "live_since": live}
