"""
Test: Feature Extraction — Verify entropy, periodicity, and feature computation.
"""

from __future__ import annotations

import unittest

from src.features.entropy import (
    domain_entropy,
    ip_set_entropy,
    ngram_likelihood,
    shannon_entropy,
)
from src.features.periodicity import (
    coefficient_of_variation,
    fft_periodicity_score,
    inter_arrival_variance,
    periodicity_score,
)


class TestShannonEntropy(unittest.TestCase):
    def test_empty_string(self):
        self.assertEqual(shannon_entropy(""), 0.0)

    def test_single_char(self):
        self.assertEqual(shannon_entropy("aaaa"), 0.0)

    def test_two_equal_chars(self):
        result = shannon_entropy("ab" * 50)
        self.assertAlmostEqual(result, 1.0, places=2)

    def test_high_entropy_random(self):
        result = shannon_entropy("abcdefghijklmnop")
        self.assertGreater(result, 3.0)


class TestIPEntropy(unittest.TestCase):
    def test_single_ip(self):
        result = ip_set_entropy(["1.2.3.4"] * 100)
        self.assertEqual(result, 0.0)

    def test_many_unique_ips(self):
        ips = [f"10.0.0.{i}" for i in range(256)]
        result = ip_set_entropy(ips)
        self.assertGreater(result, 5.0)


class TestNgramLikelihood(unittest.TestCase):
    def test_english_word(self):
        score = ngram_likelihood("information")
        # English word should have higher (less negative) score
        self.assertGreater(score, -9.0)

    def test_random_string(self):
        score = ngram_likelihood("xqzjkwvfbm")
        # Random string should have lower (more negative) score
        self.assertLess(score, -5.0)

    def test_english_scores_higher_than_random(self):
        english = ngram_likelihood("theinternetworks")
        random_str = ngram_likelihood("xqzjkwvfbmplry")
        self.assertGreater(english, random_str)


class TestDomainEntropy(unittest.TestCase):
    def test_legit_domain(self):
        result = domain_entropy("google.com")
        self.assertLess(result, 3.5)

    def test_dga_domain(self):
        result = domain_entropy("ab3kf9x2qlm7zw.com")
        self.assertGreater(result, 3.0)


class TestPeriodicity(unittest.TestCase):
    def test_regular_timestamps(self):
        """Perfect periodicity should score high."""
        timestamps = [float(i * 60) for i in range(20)]  # Every 60 seconds
        score = periodicity_score(timestamps)
        # With zero jitter, should have very high periodicity
        self.assertGreaterEqual(score, 0.0)

    def test_random_timestamps(self):
        """Random timing should score low."""
        import random
        random.seed(42)
        timestamps = sorted([random.uniform(0, 1000) for _ in range(20)])
        score = periodicity_score(timestamps)
        self.assertLess(score, 0.8)

    def test_too_few_timestamps(self):
        """Fewer than 4 timestamps should return 0."""
        self.assertEqual(fft_periodicity_score([1.0, 2.0]), 0.0)

    def test_variance_regular(self):
        """Regular intervals should have near-zero variance."""
        timestamps = [float(i * 30) for i in range(10)]
        var = inter_arrival_variance(timestamps)
        self.assertAlmostEqual(var, 0.0, places=5)

    def test_cv_regular(self):
        """Regular intervals should have zero CV."""
        timestamps = [float(i * 30) for i in range(10)]
        cv = coefficient_of_variation(timestamps)
        self.assertAlmostEqual(cv, 0.0, places=5)


if __name__ == "__main__":
    unittest.main()
