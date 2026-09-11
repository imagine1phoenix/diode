"""
DGA Domain Classifier — Training Script.

Trains an explainable Random Forest classifier on domain lexical features
to differentiate between legitimate domain names and algorithmically generated
domains (DGA) used by botnets and C2 channels.

PRD §4: Classical, lightweight ML (Random Forest) for explainability and fast inference.
Output: models/dga_rf_model.joblib
"""

from __future__ import annotations

import logging
import math
import re
import string
from collections import Counter
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, roc_auc_score
from sklearn.model_selection import train_test_split

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("train_dga")

# Reference English bigrams (same as feature extractor for consistency)
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
_BIGRAM_SMOOTHING = 0.0001


def extract_domain_features(domain: str) -> list[float]:
    """
    Extract 6 lexical & statistical features from a domain name:
    1. Character length
    2. Character Shannon entropy
    3. English bigram log-likelihood
    4. Vowel ratio
    5. Digit ratio
    6. Max consecutive consonants streak
    """
    cleaned = domain.lower().split(".")[0]
    cleaned = "".join(c for c in cleaned if c in string.ascii_lowercase or c.isdigit())
    if not cleaned:
        return [0.0, 0.0, -13.0, 0.0, 0.0, 0.0]

    length = float(len(cleaned))

    # 1. Entropy
    counts = Counter(cleaned)
    entropy = -sum((c / length) * math.log2(c / length) for c in counts.values())

    # 2. Bigram log-likelihood
    letters_only = "".join(c for c in cleaned if c in string.ascii_lowercase)
    if len(letters_only) >= 2:
        bigrams = [letters_only[i:i + 2] for i in range(len(letters_only) - 1)]
        ll = sum(math.log2(_ENGLISH_BIGRAMS.get(bg, _BIGRAM_SMOOTHING)) for bg in bigrams) / len(bigrams)
    else:
        ll = -13.0

    # 3. Vowel ratio
    vowels = sum(1 for c in cleaned if c in "aeiou")
    vowel_ratio = vowels / length

    # 4. Digit ratio
    digits = sum(1 for c in cleaned if c.isdigit())
    digit_ratio = digits / length

    # 5. Consecutive consonants
    max_consonants = 0
    current_consonants = 0
    consonants_set = set("bcdfghjklmnpqrstvwxyz")
    for c in cleaned:
        if c in consonants_set:
            current_consonants += 1
            max_consonants = max(max_consonants, current_consonants)
        else:
            current_consonants = 0

    return [length, entropy, ll, vowel_ratio, digit_ratio, float(max_consonants)]


# Training dataset: Representative legitimate domains vs synthetic DGA variants
LEGITIMATE_DOMAINS = [
    "google", "youtube", "facebook", "wikipedia", "amazon", "microsoft", "apple",
    "netflix", "twitter", "linkedin", "instagram", "cloudflare", "github", "stackoverflow",
    "medium", "reddit", "dropbox", "spotify", "slack", "salesforce", "zoom", "adobe",
    "nytimes", "cnn", "theguardian", "bbc", "reuters", "bloomberg", "forbes", "techcrunch",
    "weather", "accuweather", "booking", "airbnb", "tripadvisor", "walmart", "target",
    "homedepot", "ebay", "etsy", "paypal", "stripe", "chase", "bankofamerica", "wellsfargo",
    "fidelity", "vanguard", "mit", "harvard", "stanford", "berkeley", "cambridge", "oxford",
    "nih", "cdc", "who", "nasa", "esa", "europa", "whitehouse", "irs", "usps", "fedex",
    "ups", "dhl", "uber", "lyft", "doordash", "grubhub", "instacart", "openai", "anthropic",
    "huggingface", "gitlab", "bitbucket", "atlassian", "jira", "confluence", "trello",
    "notion", "figma", "canva", "coursera", "edx", "udemy", "khanacademy", "duolingo",
    "quora", "pinterest", "tumblr", "flickr", "vimeo", "twitch", "discord", "telegram",
    "signal", "whatsapp", "skype", "oracle", "cisco", "intel", "amd", "nvidia", "qualcomm",
    "samsung", "sony", "panasonic", "lg", "dell", "lenovo", "asus", "acer", "hp"
]

DGA_DOMAINS = [
    "xkjwhgfbsk", "qzwmvykpx", "zxcvbnmasdfg", "plokmijnuhby", "qazwsxedcrfv",
    "tgbyhnujmikolp", "mnbvcxzlkjhg", "poiuytrewqasdf", "lkjhgfdsaqwe", "mnbvcxzasdfgh",
    "dfgthzujikol", "wertzuiopasdf", "yxcvbnmasdfg", "vbnmqwertyui", "asdfghjklyxcv",
    "ghjklqwertyu", "ertzuikolmnb", "cvbnmasdfghj", "qwertzuiopas", "yxcvbnmqwerty",
    "a1b2c3d4e5f6g7", "9876543210zyx", "1a2b3c4d5e6f", "8h7g6f5e4d3c", "0z9y8x7w6v5u",
    "k9j8h7g6f5d4", "m1n2b3v4c5x6", "l7k6j5h4g3f2", "p9o8i7u6y5t4", "q1w2e3r4t5y6",
    "z8y7x6w5v4u3", "b2c3d4f5g6h7", "j9k8l7m6n5p4", "r1s2t3v4w5x6", "t9u8v7w6x5y4",
    "f1g2h3j4k5l6", "c8v7b6n5m4l3", "k1j2h3g4f5d6", "w9e8r7t6y5u4", "x1c2v3b4n5m6",
    "vxkprmztwq", "blmztpqkxy", "qwrtypzxcv", "dfghjklmnb", "zxcvbnmqwr",
    "plmkonjiub", "qazxswedcv", "rfvtgbyhnj", "ujmikolpqa", "wsxedcrfvt",
    "gbyhnujmik", "olpqazwsxe", "dcrfvtgbyh", "nujmikolpq", "azwsxedcrf",
    "vtgbyhnujm", "ikolpqazws", "xedcrfvtgb", "yhnujmikol", "pqazwsxedc",
    "rfvtgbyhnu", "jmikolpqaz", "wsxedcrfvt", "gbyhnujmik", "olpqazwsxe",
    "jkhgfdsaqw", "poiuytrewq", "zxcvbnmlkj", "hgfdsaqwpo", "iuytrewqzx",
    "cvbnmlkjhg", "fdsaqwerty", "uioplkjhgf", "dsazxcvbnm", "qwertyuiop",
    "asdfghjklz", "xcvbnmqwer", "tyuiopasdf", "ghjklzxcvb", "nmqwertyui",
    "opasdfghjk", "lzxcvbnmqw", "ertyuiopas", "dfghjklzxc", "vbnmqwerty"
]


def train_and_save_model(output_path: Path) -> RandomForestClassifier:
    """Train Random Forest model and save serialized joblib artifact."""
    logger.info("Extracting features for %d legit and %d DGA domains...", len(LEGITIMATE_DOMAINS), len(DGA_DOMAINS))

    X = []
    y = []

    for dom in LEGITIMATE_DOMAINS:
        X.append(extract_domain_features(dom))
        y.append(0)  # 0 = Benign / Legitimate

    for dom in DGA_DOMAINS:
        X.append(extract_domain_features(dom))
        y.append(1)  # 1 = Malicious DGA

    X_arr = np.array(X, dtype=np.float32)
    y_arr = np.array(y, dtype=np.int64)

    X_train, X_test, y_train, y_test = train_test_split(
        X_arr, y_arr, test_size=0.25, random_state=42, stratify=y_arr
    )

    clf = RandomForestClassifier(
        n_estimators=50,
        max_depth=8,
        min_samples_split=3,
        random_state=42,
    )
    clf.fit(X_train, y_train)

    y_pred = clf.predict(X_test)
    y_prob = clf.predict_proba(X_test)[:, 1]

    roc_auc = roc_auc_score(y_test, y_prob)
    logger.info("Training complete. ROC-AUC: %.4f", roc_auc)
    logger.info("\n%s", classification_report(y_test, y_pred, target_names=["Benign", "DGA"]))

    output_path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "model": clf,
        "feature_names": [
            "length",
            "shannon_entropy",
            "bigram_log_likelihood",
            "vowel_ratio",
            "digit_ratio",
            "max_consecutive_consonants",
        ],
        "feature_importances": dict(zip(
            ["length", "entropy", "bigrams", "vowel_ratio", "digit_ratio", "consonants"],
            clf.feature_importances_
        )),
        "version": "1.0.0",
        "algorithm": "RandomForestClassifier",
    }
    joblib.dump(payload, output_path)
    logger.info("Saved trained DGA Random Forest artifact to: %s", output_path)
    return clf


if __name__ == "__main__":
    out_dir = Path(__file__).parent.parent.parent / "models"
    out_file = out_dir / "dga_rf_model.joblib"
    train_and_save_model(out_file)
