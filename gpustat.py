#!/usr/bin/env python3
"""GPU use of the two local models on this host (DGX Spark / GB10), for AI pipeline monitoring > Models > "GPU use".

  gpustat.py           sampler: long-running scheduler job "gpu" (exits hourly so code changes apply; the scheduler
                       restarts it). Streams `nvidia-smi pmon` (per-process SM busy %, every SAMPLE_S seconds) and
                       `nvidia-smi --query-gpu` (whole-GPU busy % and power) and writes one row per minute.
  gpustat.py show      the last hour of rows

Processes are attributed by their command line: SGLang = decision model (clef), vLLM = event reviewer (gemma4-26b),
anything else (desktop, other CUDA jobs) = other. SM % per process is NVIDIA's own per-process sampling, so the parts
are approximate (they can sum a little above or below the whole-GPU figure). Storage: table gpu_usage in netmon.db
(store.tl_conn), kept KEEP_DAYS. The dashboard reads it through series().
"""
import os
import shutil
import subprocess
import sys
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import store  # noqa: E402

SAMPLE_S = 5
KEEP_DAYS = 30
RUN_S = 3600
NVSMI = shutil.which("nvidia-smi", path="/usr/bin:/usr/local/bin:/usr/local/nvidia/bin") or "/usr/bin/nvidia-smi"  # fixed locations: never from the environment
DDL = """CREATE TABLE IF NOT EXISTS gpu_usage (
  ts INTEGER PRIMARY KEY, n INTEGER NOT NULL, decision REAL NOT NULL, reviewer REAL NOT NULL, other REAL NOT NULL,
  util REAL, power REAL, decision_mb REAL, reviewer_mb REAL) WITHOUT ROWID"""
PARTS = ("decision", "reviewer", "other")


def init(c):
    c.execute(DDL)
    return c


def conn():
    return store.tl_conn("gpustat", init)


_kind = {}


def kind_of(pid, name=""):
    """decision / reviewer / other for a host pid (cached; pids are not reused within an hourly run in practice)."""
    k = _kind.get(pid)
    if k:
        return k
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as f:
            cmd = f.read().replace(b"\0", b" ").decode(errors="replace").lower()
    except OSError:
        cmd = ""
    cmd = cmd or str(name).lower()
    k = "decision" if "sglang" in cmd else "reviewer" if "vllm" in cmd else "other"
    _kind[pid] = k
    return k


def parse_pmon(line):
    """One `nvidia-smi pmon -o DT -s um` row -> (stamp, pid, part, sm %, fb MB) or None (headers, blank)."""
    f = line.split()
    if len(f) < 14 or line.lstrip().startswith("#"):
        return None
    try:
        pid = int(f[3])
    except ValueError:
        return None
    num = lambda v: float(v) if v not in ("-", "") else 0.0  # noqa: E731
    try:
        return f[0] + f[1], pid, kind_of(pid, f[13]), num(f[5]), num(f[11])
    except ValueError:
        return None


class Minute:
    """Accumulates samples of the current minute; row() averages them."""
    def __init__(self, ts):
        self.ts, self.stamps, self.sm, self.mb, self.util, self.power = ts, set(), dict.fromkeys(PARTS, 0.0), {}, [], []

    def add_proc(self, stamp, pid, part, sm, mb):
        self.stamps.add(stamp)
        self.sm[part] += sm
        self.mb.setdefault(stamp, dict.fromkeys(PARTS, 0.0))[part] += mb

    def row(self):
        n = max(1, len(self.stamps))
        mbs = list(self.mb.values())
        avg_mb = {p: (sum(m[p] for m in mbs) / len(mbs)) if mbs else None for p in PARTS}
        return (self.ts, len(self.stamps), round(min(100.0, self.sm["decision"] / n), 2), round(min(100.0, self.sm["reviewer"] / n), 2),
                round(min(100.0, self.sm["other"] / n), 2), round(sum(self.util) / len(self.util), 2) if self.util else None,
                round(sum(self.power) / len(self.power), 2) if self.power else None, avg_mb["decision"], avg_mb["reviewer"])


def _write(rows):
    c = conn()
    c.executemany("INSERT OR REPLACE INTO gpu_usage (ts, n, decision, reviewer, other, util, power, decision_mb, reviewer_mb) VALUES (?,?,?,?,?,?,?,?,?)", rows)
    c.execute("DELETE FROM gpu_usage WHERE ts < ?", (int(time.time()) - KEEP_DAYS * 86400,))


def _stamp_ts(stamp):
    """pmon's local "YYYYMMDDHH:MM:SS" -> epoch seconds (None when unreadable)."""
    try:
        return int(time.mktime(time.strptime(stamp, "%Y%m%d%H:%M:%S")))
    except ValueError:
        return None


def run(seconds=RUN_S):
    lock = threading.Lock()
    mins = {}  # minute start -> Minute; a pmon sample goes to the minute of its own time stamp (never split)
    stop = time.time() + seconds

    def minute(ts):
        ts = int(ts) // 60 * 60
        m = mins.get(ts)
        if m is None:
            m = mins[ts] = Minute(ts)
        return m

    def flush(final=False):
        cut = int(time.time()) // 60 * 60 - 60  # keep the current and previous minute open (late lines)
        done = [mins.pop(t) for t in sorted(mins) if final or t < cut]
        rows = [m.row() for m in done if m.stamps or m.util]
        if rows:
            try:
                _write(rows)
            except Exception as e:  # noqa: BLE001
                print(f"gpustat: write failed: {e}", file=sys.stderr, flush=True)

    pm = subprocess.Popen([NVSMI, "pmon", "-o", "DT", "-s", "um", "-d", str(SAMPLE_S)], stdout=subprocess.PIPE, text=True)  # noqa: S603
    qg = subprocess.Popen([NVSMI, "--query-gpu=utilization.gpu,power.draw", "--format=csv,noheader,nounits", "-l", str(SAMPLE_S)],  # noqa: S603
                          stdout=subprocess.PIPE, text=True)

    def read_q():
        for line in qg.stdout or []:
            p = [x.strip() for x in line.split(",")]
            with lock:
                m = minute(time.time())
                try:
                    m.util.append(float(p[0]))
                except (ValueError, IndexError):
                    pass
                try:
                    m.power.append(float(p[1]))
                except (ValueError, IndexError):
                    pass
    threading.Thread(target=read_q, daemon=True).start()
    last = time.time()
    try:
        for line in pm.stdout or []:
            r = parse_pmon(line)
            if r:
                ts = _stamp_ts(r[0]) or time.time()
                with lock:
                    minute(ts).add_proc(*r)
            if time.time() - last >= 20:
                last = time.time()
                with lock:
                    flush()
            if time.time() >= stop:
                break
    finally:
        for p in (pm, qg):
            p.terminate()
        with lock:
            flush(final=True)
    return 0 if time.time() >= stop else 1


def series(days=7, step_min=15, tz_min=0, c=None):
    """Chart data: average busy % per step_min bucket for the last `days` days (buckets aligned in the browser's zone)."""
    days = max(1, min(int(days), KEEP_DAYS))
    step = max(1, min(int(step_min), 240)) * 60
    off = max(-14 * 60, min(int(tz_min), 14 * 60)) * 60
    c = c or conn()
    since = int(time.time()) - days * 86400
    rows = c.execute("""SELECT ((ts + ?) / ?) * ? - ? AS b, COUNT(*), AVG(decision), AVG(reviewer), AVG(other), AVG(util), AVG(power),
                        AVG(decision_mb), AVG(reviewer_mb) FROM gpu_usage WHERE ts >= ? GROUP BY b ORDER BY b""",
                     (off, step, step, off, since)).fetchall()
    pts = [{"t": r[0], "minutes": r[1], "decision": round(r[2], 2), "reviewer": round(r[3], 2), "other": round(r[4], 2),
            "util": None if r[5] is None else round(r[5], 2), "power": None if r[6] is None else round(r[6], 1),
            "decision_gb": None if r[7] is None else round(r[7] / 1024, 1), "reviewer_gb": None if r[8] is None else round(r[8] / 1024, 1)} for r in rows]
    tot = c.execute("SELECT COUNT(*), AVG(decision), AVG(reviewer), AVG(other), AVG(util), AVG(power), MIN(ts) FROM gpu_usage WHERE ts >= ?", (since,)).fetchone()
    first = c.execute("SELECT MIN(ts) FROM gpu_usage").fetchone()[0]
    return {"points": pts, "step_min": step // 60, "days": days, "first": first,
            "avg": {"minutes": tot[0], "decision": tot[1], "reviewer": tot[2], "other": tot[3], "util": tot[4], "power": tot[5]}}


def main(argv):
    if argv[1:2] == ["show"]:
        for r in conn().execute("SELECT * FROM gpu_usage WHERE ts >= ? ORDER BY ts", (int(time.time()) - 3600,)):
            print(tuple(r))
        return 0
    return run(int(argv[1]) if len(argv) > 1 else RUN_S)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
