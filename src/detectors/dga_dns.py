"""
DGA / DNS Tunnelling Detector.

PRD §7 row 4 — Tier 1 (must ship, demo-ready).

Features used:
    - domain_name_entropy (per-flow)
    - n-gram likelihood vs dictionary corpus (per-flow)
    - query_length (per-flow)
    - TXT/NULL record ratio (per-flow)

Approach: Entropy + lightweight n-gram classifier.
    DGA-generated domains have high character entropy and low n-gram
    likelihood compared to legitimate domain names. DNS tunnelling
    uses abnormally long queries and TXT/NULL record types.

Evidence populated:
    - features_triggered: which entropy/ngram/length thresholds fired
    - supporting_stats: entropy value, ngram score, query samples

Known false-positive scenarios (R8.4):
    - Base64-encoded CDN subdomains (e.g., Cloudflare, Akamai)
    - Internationalized domain names with unusual character distributions
    - Legitimate TXT record lookups (SPF, DKIM, DMARC)

rules.md R1.1: No external DNS resolution — analysis is on query strings only.
"""

from __future__ import annotations

import logging

import joblib

import config
from src.alert.schema import Severity, ThreatClass
from src.detectors.base import BaseDetector, RawDetection
from src.features.extractor import FlowFeatures, WindowFeatures
from src.models.train_dga import extract_domain_features

logger = logging.getLogger(__name__)


class DGADNSDetector(BaseDetector):
    """
    Detects DGA-generated domain names and DNS tunnelling using
    a trained Random Forest ML model alongside character entropy,
    n-gram analysis, and query metadata.
    """

    def __init__(self) -> None:
        super().__init__()
        self.rf_model = None
        self.feature_names: list[str] = []
        self.feature_importances: dict[str, float] = {}
        model_path = config.MODELS_DIR / "dga_rf_model.joblib"
        if model_path.exists():
            try:
                payload = joblib.load(model_path)
                self.rf_model = payload.get("model")
                self.feature_names = payload.get("feature_names", [])
                self.feature_importances = payload.get("feature_importances", {})
                logger.info("Loaded trained DGA Random Forest classifier from %s", model_path)
            except Exception as e:
                logger.warning("Could not load DGA ML model, falling back to rule-based: %s", e)

    @property
    def name(self) -> str:
        return "DGA / DNS Tunnelling Detector (AI-Powered)"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def threat_class(self) -> ThreatClass:
        return ThreatClass.DGA_DNS

    def detect(
        self,
        flow_features: FlowFeatures,
        window_features: WindowFeatures,
    ) -> list[RawDetection]:
        """
        Analyse DNS query features for DGA/tunnelling indicators.

        Detection logic:
        1. Skip non-DNS flows
        2. Check domain name entropy (high = random = DGA)
        3. Check n-gram likelihood (low = unlike natural language)
        4. Check query length (long = tunnelling)
        5. Check TXT/NULL record ratio (high = tunnelling)
        """
        # Only analyse flows with DNS activity
        if not flow_features.has_dns:
            return []

        triggered: list[str] = []
        stats: dict[str, object] = {}
        score = 0.0

        # --- Feature 1: Domain name entropy ---
        if flow_features.domain_name_entropy > config.DGA_ENTROPY_THRESHOLD:
            triggered.append("domain_name_entropy")
            # Score proportional to excess entropy
            excess = (
                flow_features.domain_name_entropy - config.DGA_ENTROPY_THRESHOLD
            )
            score += min(excess / 2.0, 0.35)
            stats["domain_name_entropy"] = round(
                flow_features.domain_name_entropy, 4
            )
            stats["entropy_threshold"] = config.DGA_ENTROPY_THRESHOLD

        # --- Feature 2: N-gram likelihood ---
        # ngram_likelihood_score is negative (log-likelihood);
        # more negative = less English-like
        if flow_features.ngram_likelihood_score < config.DGA_NGRAM_THRESHOLD:
            triggered.append("ngram_likelihood")
            score += 0.3
            stats["ngram_likelihood"] = round(
                flow_features.ngram_likelihood_score, 4
            )
            stats["ngram_threshold"] = config.DGA_NGRAM_THRESHOLD

        # --- Feature 3: Query length ---
        if flow_features.query_length > config.DGA_QUERY_LENGTH_THRESHOLD:
            triggered.append("query_length")
            # Longer queries → more likely tunnelling
            ratio = flow_features.query_length / config.DGA_QUERY_LENGTH_THRESHOLD
            score += min(ratio / 5.0, 0.2)
            stats["query_length"] = flow_features.query_length
            stats["query_length_threshold"] = config.DGA_QUERY_LENGTH_THRESHOLD

        # --- Feature 4: TXT/NULL record ratio ---
        if flow_features.txt_null_record_ratio > 0.5:
            triggered.append("txt_null_record_ratio")
            score += 0.15
            stats["txt_null_record_ratio"] = round(
                flow_features.txt_null_record_ratio, 4
            )

        # --- Feature 5: Trained Random Forest Classifier (PRD §4 "AI-Based") ---
        query_text = flow_features.dns_query or ""
        if self.rf_model is not None and query_text:
            try:
                feat_vec = extract_domain_features(query_text)
                prob_dga = float(self.rf_model.predict_proba([feat_vec])[0][1])
                stats["ml_model"] = "RandomForest-v1.0"
                stats["ml_dga_probability"] = round(prob_dga, 4)
                if prob_dga >= 0.50:
                    triggered.append("ml_random_forest")
                    score += prob_dga * 0.45
            except Exception as e:
                logger.debug("Random Forest inference error: %s", e)

        # --- Emit detection if any features triggered ---
        if not triggered:
            return []

        confidence = min(score, 1.0)
        severity = self._map_severity(confidence, triggered)

        logger.info(
            "DGA/DNS detected: flow=%s confidence=%.2f entropy=%.3f ngram=%.3f",
            flow_features.flow_id, confidence,
            flow_features.domain_name_entropy,
            flow_features.ngram_likelihood_score,
        )

        return [
            self._make_detection(
                flow_id=flow_features.flow_id,
                confidence=confidence,
                severity=severity,
                features_triggered=triggered,
                supporting_stats=stats,
            )
        ]

    @staticmethod
    def _map_severity(confidence: float, triggered: list[str]) -> Severity:
        """
        Map to severity with strict confidence-severity alignment (PRD §6).
        DNS tunnelling (query_length + TXT/NULL) with multi-feature proof
        qualifies for CRITICAL.
        """
        is_tunnelling = (
            "query_length" in triggered or "txt_null_record_ratio" in triggered
        )
        if confidence >= 0.88 and (is_tunnelling or len(triggered) >= 2):
            return Severity.CRITICAL
        if confidence >= 0.72:
            return Severity.HIGH
        if confidence >= 0.55:
            return Severity.MEDIUM
        return Severity.LOW

