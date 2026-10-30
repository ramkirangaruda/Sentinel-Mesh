#!/usr/bin/env python3
"""Tests for drain_bound.py: python -m unittest paper/analysis/test_drain_bound.py (from repo root)."""
import os, sys, unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import drain_bound as db  # noqa: E402


class TestBudgetedBound(unittest.TestCase):
    def test_matches_formula(self):
        self.assertAlmostEqual(db.budgeted_bound_j(100.0, 20.0, 0.05), 20.0 + 0.05 * 100.0)

    def test_monotonic_in_time(self):
        a = db.budgeted_bound_j(10.0)
        b = db.budgeted_bound_j(1000.0)
        self.assertLess(a, b)

    def test_avg_power_converges_to_refill_rate(self):
        long_run = db.long_run_budgeted_power_mw(0.05)
        p_short = db.budgeted_bound_avg_power_mw(10.0, 20.0, 0.05)
        p_long = db.budgeted_bound_avg_power_mw(1e9, 20.0, 0.05)
        self.assertGreater(p_short, long_run)            # short horizon: the full bucket dominates
        self.assertAlmostEqual(p_long, long_run, places=3)  # long horizon: converges to r

    def test_simulated_spend_sequence_never_exceeds_the_bound(self):
        """A simple simulation of an EnergyBudget-like bucket: whatever spend pattern is tried
        (bursty, adaptive, worst-case), cumulative spend must stay at or under Eq. (1)."""
        capacity, refill = 20.0, 0.05
        balance = capacity
        t = 0.0
        dt = 0.1
        spent_total = 0.0
        import random
        random.seed(0)
        while t < 5000.0:
            balance = min(capacity, balance + refill * dt)
            cost = random.choice([0.0, 0.02, 0.0005, 0.5])  # try to spend aggressively, including a cheat value
            if balance >= cost:
                balance -= cost
                spent_total += cost
            t += dt
            self.assertLessEqual(spent_total, db.budgeted_bound_j(t, capacity, refill) + 1e-9)


class TestUnbudgetedBound(unittest.TestCase):
    def test_rate_matches_pacer_cap(self):
        self.assertAlmostEqual(db.max_attempt_rate_hz(5, 5000), 1.0)
        self.assertAlmostEqual(db.max_attempt_rate_hz(10, 2000), 5.0)

    def test_unbudgeted_power_scales_with_rate_and_cost(self):
        p1 = db.unbudgeted_power_mw(1.0, max_in_window=5, window_ms=5000)
        p2 = db.unbudgeted_power_mw(2.0, max_in_window=5, window_ms=5000)
        self.assertAlmostEqual(p2, 2 * p1)


class TestCLI(unittest.TestCase):
    def test_total_equals_sum_of_parts(self):
        t = 600.0
        rx = 2.0
        total = db.total_worst_case_mw(t, rx)
        budgeted = db.budgeted_bound_avg_power_mw(t)
        unbudgeted = db.unbudgeted_power_mw(rx)
        self.assertAlmostEqual(total, budgeted + unbudgeted)


if __name__ == "__main__":
    unittest.main()
