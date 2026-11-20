"""Unit tests for dashboard/app/aiusage.py: hourly token totals behind AI pipeline monitoring > Tokens chart."""
import os, sys; sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__)))); import _env  # noqa: E401,E402

import unittest  # noqa: E402
from unittest import mock  # noqa: E402

import aiusage  # noqa: E402
import llm_providers  # noqa: E402


class AiUsage(unittest.TestCase):
    def setUp(self):
        aiusage.flush()
        with aiusage._db() as c:
            c.execute("DELETE FROM ai_usage")

    def test_sums_per_step_and_prices(self):
        """Calls add up per step; purposes map to steps; unknown purposes are ignored; cost only when priced.
        REQ: LLM-04"""
        aiusage.record("correlation", "clef", "clef-m", 100, 0)
        aiusage.record("correlation", "clef", "clef-m", 50, 0)
        aiusage.record(aiusage.step_of("event-classify"), "api:x", "rev", 1000, 200, 400)
        aiusage.record(aiusage.step_of("chat"), "api:x", "rev", 9999, 9999)  # Ask AI is not part of this chart
        with mock.patch.object(llm_providers, "price", lambda p, m: None):
            v = aiusage.view(1)
        b = v["buckets"][-1]
        self.assertEqual(b["tokens"]["correlation"], 150)
        self.assertEqual(b["calls"]["correlation"], 2)
        self.assertEqual(b["tokens"]["event-review"], 1200)
        self.assertNotIn("chat", b["tokens"])
        self.assertFalse(v["priced"])
        self.assertEqual(b["cost"], {})
        with mock.patch.object(llm_providers, "price", lambda p, m: {"in": 1.0, "out": 10.0, "cache_read": 0.1}):
            v = aiusage.view(1)
        self.assertTrue(v["priced"])
        c = v["buckets"][-1]["cost"]
        self.assertAlmostEqual(c["event-review"], (600 * 1.0 + 400 * 0.1 + 200 * 10.0) / 1e6)
        self.assertNotIn("correlation", c)  # the local decision model is never billed

    def test_bad_input_never_raises(self):
        """Accounting never breaks a model call. REQ: LLM-04"""
        aiusage.record("correlation", None, None, "x", None)
        aiusage.record("nope", "a", "b", 1, 1)
        self.assertIsInstance(aiusage.view(1000)["buckets"], list)


if __name__ == "__main__":
    unittest.main()
