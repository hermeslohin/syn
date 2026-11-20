"""Unit tests for gpustat.py: GPU busy % per local model (AI pipeline monitoring > GPU use)."""
import os, sys; sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__)))); import _env  # noqa: E401,E402

import time  # noqa: E402
import unittest  # noqa: E402

import gpustat  # noqa: E402


class GpuStat(unittest.TestCase):
    def setUp(self):
        _env.fresh_db()
        gpustat._kind.clear()

    def test_parse_and_attribute(self):
        """pmon rows are attributed by command line; headers and '-' values are handled. REQ: LLM-05"""
        gpustat._kind.update({11: "decision", 22: "reviewer"})
        self.assertIsNone(gpustat.parse_pmon("#Date Time gpu pid type sm mem enc dec jpg ofa fb ccpm command"))
        r = gpustat.parse_pmon(" 20261115    14:01:33       0       11     C      4      0      -      -      -      -  34063      0    sglang::schedul")
        self.assertEqual(r[1:], (11, "decision", 4.0, 34063.0))
        r = gpustat.parse_pmon(" 20261115    14:01:33       0       22     C      -      -      -      -      -      -  32358      0    VLLM::EngineCor")
        self.assertEqual(r[2:4], ("reviewer", 0.0))
        self.assertEqual(gpustat.kind_of(999999999, "Xorg"), "other")

    def test_minute_average_and_series(self):
        """A minute averages its samples per part; series() buckets and averages the minutes. REQ: LLM-05"""
        now = int(time.time()) // 60 * 60 - 120
        m = gpustat.Minute(now)
        for st, sm in (("a", 10), ("b", 30)):
            m.add_proc(st, 1, "decision", sm, 1000)
            m.add_proc(st, 2, "reviewer", 4, 2000)
        m.util += [20, 40]
        row = m.row()
        self.assertEqual(row[1:6], (2, 20.0, 4.0, 0.0, 30.0))
        gpustat._write([row, (now - 60, 2, 0.0, 10.0, 1.0, 5.0, 20.0, 1000, 2000)])
        v = gpustat.series(7, 30)
        self.assertEqual(v["avg"]["minutes"], 2)
        self.assertAlmostEqual(v["avg"]["decision"], 10.0)
        self.assertAlmostEqual(v["avg"]["reviewer"], 7.0)
        self.assertTrue(v["points"])


if __name__ == "__main__":
    unittest.main()
