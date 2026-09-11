"""
Periodicity Analysis — FFT-based beaconing detection.

Used by C2 Beaconing detector (PRD §7 row 3).
Features: inter-arrival time variance, periodicity score (FFT or autocorrelation).

rules.md R5: No DNS-based detection here — that belongs to DGA detector.
"""

from __future__ import annotations

import logging

import numpy as np

logger = logging.getLogger(__name__)


def compute_inter_arrival_times(timestamps: list[float]) -> np.ndarray:
    """
    Compute inter-arrival times from a sorted list of timestamps.

    Args:
        timestamps: Sorted list of packet/flow timestamps (epoch seconds).

    Returns:
        Array of inter-arrival times (seconds). Length = len(timestamps) - 1.
    """
    if len(timestamps) < 2:
        return np.array([])
    ts = np.array(sorted(timestamps))
    return np.diff(ts)


def inter_arrival_variance(timestamps: list[float]) -> float:
    """
    Compute variance of inter-arrival times.
    Low variance → regular intervals → suspicious beaconing.

    Args:
        timestamps: Sorted list of packet/flow timestamps.

    Returns:
        Variance of inter-arrival times. 0.0 if fewer than 2 timestamps.
    """
    iat = compute_inter_arrival_times(timestamps)
    if len(iat) == 0:
        return 0.0
    return float(np.var(iat))


def coefficient_of_variation(timestamps: list[float]) -> float:
    """
    Compute coefficient of variation (CV) of inter-arrival times.
    CV = std / mean. Low CV → regular intervals → beaconing.

    Args:
        timestamps: Sorted list of timestamps.

    Returns:
        CV value. 0.0 if fewer than 2 timestamps or mean is 0.
    """
    iat = compute_inter_arrival_times(timestamps)
    if len(iat) == 0:
        return 0.0
    mean = float(np.mean(iat))
    if mean == 0.0:
        return 0.0
    return float(np.std(iat)) / mean


def fft_periodicity_score(timestamps: list[float]) -> float:
    """
    Detect periodicity in connection timestamps using FFT.

    Approach:
        1. Compute inter-arrival times
        2. Apply FFT to the IAT sequence
        3. Look for dominant frequency peaks
        4. Score based on the ratio of peak power to total power

    A high score (close to 1.0) indicates strong periodicity = likely C2 beaconing.
    A low score (close to 0.0) indicates random timing = normal traffic.

    Args:
        timestamps: List of connection timestamps (epoch seconds).

    Returns:
        Periodicity score in [0.0, 1.0].
    """
    iat = compute_inter_arrival_times(timestamps)

    # Need at least 4 IATs for meaningful FFT
    if len(iat) < 4:
        return 0.0

    # Remove mean (DC component) to focus on periodic signal
    iat_centered = iat - np.mean(iat)

    # Apply FFT
    fft_vals = np.fft.rfft(iat_centered)
    magnitudes = np.abs(fft_vals)

    # Skip DC component (index 0)
    if len(magnitudes) < 2:
        return 0.0
    magnitudes = magnitudes[1:]

    total_power = float(np.sum(magnitudes ** 2))
    if total_power == 0.0:
        return 0.0

    # Peak power ratio — how much power is concentrated in the top frequency
    peak_power = float(np.max(magnitudes) ** 2)
    score = peak_power / total_power

    # Clamp to [0, 1]
    return min(max(score, 0.0), 1.0)


def autocorrelation_periodicity(timestamps: list[float]) -> float:
    """
    Alternative periodicity detection using autocorrelation.

    Looks for repeating patterns in inter-arrival times by computing
    normalized autocorrelation and finding the highest non-trivial peak.

    Args:
        timestamps: List of connection timestamps.

    Returns:
        Periodicity score in [0.0, 1.0].
    """
    iat = compute_inter_arrival_times(timestamps)

    if len(iat) < 4:
        return 0.0

    # Normalize
    iat_norm = iat - np.mean(iat)
    variance = float(np.var(iat_norm))
    if variance == 0.0:
        # Perfect regularity — all IATs identical → maximum beaconing signal
        return 1.0

    # Compute autocorrelation for lags 1 to len//2
    n = len(iat_norm)
    max_lag = n // 2
    autocorr = np.zeros(max_lag)

    for lag in range(1, max_lag):
        autocorr[lag] = float(
            np.sum(iat_norm[:n - lag] * iat_norm[lag:]) / (n * variance)
        )

    if len(autocorr) < 2:
        return 0.0

    # Score is the max autocorrelation value (excluding lag 0)
    peak = float(np.max(autocorr[1:]))
    return min(max(peak, 0.0), 1.0)


def periodicity_score(timestamps: list[float]) -> float:
    """
    Combined periodicity score using both FFT and autocorrelation.
    Takes the maximum of both methods for robustness.

    Args:
        timestamps: List of connection timestamps.

    Returns:
        Periodicity score in [0.0, 1.0].
    """
    fft_score = fft_periodicity_score(timestamps)
    acf_score = autocorrelation_periodicity(timestamps)
    return max(fft_score, acf_score)
