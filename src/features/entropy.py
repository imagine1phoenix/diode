"""
Entropy & N-gram Utilities — Shared feature helpers.

Used by:
  - DDoS detector: source-IP entropy (PRD §7)
  - DGA/DNS detector: domain name entropy + n-gram likelihood (PRD §7)

rules.md R5: Uses exactly the features specified in the PRD.
"""

from __future__ import annotations

import math
import string
from collections import Counter


def shannon_entropy(data: str | list[str]) -> float:
    """
    Calculate Shannon entropy of a string or list of tokens.

    For strings: treats each character as a symbol.
    For lists: treats each element as a symbol.

    Returns:
        Entropy value in bits. Higher = more random.
        0.0 for empty input.
    """
    if not data:
        return 0.0

    counts = Counter(data)
    total = len(data)
    entropy = 0.0

    for count in counts.values():
        if count == 0:
            continue
        p = count / total
        entropy -= p * math.log2(p)

    return entropy


def ip_set_entropy(ip_addresses: list[str]) -> float:
    """
    Calculate entropy over a set of IP addresses.
    Used for DDoS source-IP entropy (PRD §7 row 1).

    Low entropy → few unique sources (possible targeted DDoS or single-source).
    High entropy → many diverse sources (distributed attack or benign traffic).

    Args:
        ip_addresses: List of IP address strings.

    Returns:
        Shannon entropy in bits.
    """
    return shannon_entropy(ip_addresses)


# ---------------------------------------------------------------------------
# N-gram model for DGA detection (PRD §7 row 4)
# ---------------------------------------------------------------------------

# English bigram frequencies (normalized, derived from common English text).
# Used as the reference corpus for n-gram likelihood scoring.
_ENGLISH_BIGRAMS: dict[str, float] = {
    "th": 0.0356, "he": 0.0307, "in": 0.0243, "er": 0.0205, "an": 0.0199,
    "re": 0.0185, "on": 0.0176, "at": 0.0149, "en": 0.0145, "nd": 0.0135,
    "ti": 0.0134, "es": 0.0134, "or": 0.0128, "te": 0.0120, "of": 0.0117,
    "ed": 0.0117, "is": 0.0113, "it": 0.0112, "al": 0.0109, "ar": 0.0107,
    "st": 0.0105, "to": 0.0104, "nt": 0.0104, "ng": 0.0095, "se": 0.0093,
    "ha": 0.0093, "as": 0.0087, "ou": 0.0087, "io": 0.0083, "le": 0.0083,
    "ve": 0.0083, "co": 0.0079, "me": 0.0079, "de": 0.0076, "hi": 0.0076,
    "ri": 0.0073, "ro": 0.0073, "ic": 0.0070, "ne": 0.0069, "ea": 0.0069,
    "ra": 0.0069, "ce": 0.0065, "li": 0.0062, "ch": 0.0060, "ll": 0.0058,
    "be": 0.0058, "ma": 0.0057, "si": 0.0055, "om": 0.0055, "ur": 0.0054,
}

# Smoothing value for unseen bigrams
_BIGRAM_SMOOTHING: float = 0.0001


def ngram_likelihood(domain: str, n: int = 2) -> float:
    """
    Score a domain name against English n-gram frequencies.
    Lower score = more random / likely DGA-generated.

    Args:
        domain: Domain name string (without TLD).
        n: N-gram size (default: bigrams).

    Returns:
        Average log-likelihood per n-gram. Range is negative;
        closer to 0 = more English-like.
    """
    # Clean domain: lowercase, remove dots and digits
    cleaned = "".join(c for c in domain.lower() if c in string.ascii_lowercase)
    if len(cleaned) < n:
        return -10.0  # Too short to score meaningfully

    ngrams = [cleaned[i:i + n] for i in range(len(cleaned) - n + 1)]
    total_ll = 0.0

    for ng in ngrams:
        freq = _ENGLISH_BIGRAMS.get(ng, _BIGRAM_SMOOTHING)
        total_ll += math.log2(freq)

    return total_ll / len(ngrams)


def domain_entropy(domain: str) -> float:
    """
    Calculate character-level Shannon entropy of a domain name.
    Used for DGA detection (PRD §7 row 4).

    High entropy → random-looking → likely DGA.
    Low entropy → structured → likely legitimate.

    Args:
        domain: Domain name string (e.g., "ab3kf9x2.evil.com").

    Returns:
        Shannon entropy in bits.
    """
    # Strip the TLD(s) — only analyse the hostname part
    parts = domain.split(".")
    if len(parts) > 1:
        hostname = ".".join(parts[:-1])  # Remove last TLD
    else:
        hostname = domain
    return shannon_entropy(hostname)
