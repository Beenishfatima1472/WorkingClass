"""
maci_model.py — MACI v4 Model Loader
Loads the trained ml_model.pkl from maci_v4 and exposes
a simple predict_authenticity() function for the Streamlit app.

Option B: model weights are local — training code stays private.
"""

import os
import re
import pickle
from pathlib import Path
from typing import Dict, Optional

# ── Model state ───────────────────────────────────────────────────────
_bundle   = None   # the full pkl bundle from maci_v4
_loaded   = False

# Where to look for the pkl file (in priority order)
_SEARCH_PATHS = [
    "models/ml_model.pkl",           # GitHub repo → models/
    "maci_v4_models/ml_model.pkl",   # SageMaker output
    "ml_model.pkl",                  # root fallback
]

LABEL_NAMES = {
    0: "Authentic",
    1: "Riba (Usury/Interest)",
    2: "Gharar (Excessive Uncertainty)",
    3: "Maysir (Gambling/Speculation)",
    4: "Fabricated/Unauthorized Fatwa",
    5: "Quran/Hadith Fabrication",
    6: "MLM / Pyramid Scheme",
    7: "Scholar Misquotation",
}


def _try_load() -> bool:
    global _bundle, _loaded
    for path in _SEARCH_PATHS:
        if Path(path).exists():
            try:
                with open(path, "rb") as f:
                    _bundle = pickle.load(f)
                _loaded = True
                return True
            except Exception as e:
                print(f"[maci_model] Failed to load {path}: {e}")
    return False


def model_available() -> bool:
    if _loaded:
        return True
    return _try_load()


def predict_authenticity(text: str) -> Optional[Dict]:
    """
    Run the v4 ML model on a text string.

    Returns None if model weights are not loaded.

    Returns dict:
        authenticity_score   float 0-1   (higher = more authentic)
        top_violation        str         label name of top violation
        top_violation_id     int         label id
        confidence           float
        requires_review      bool        True if confidence 0.50-0.72
        all_probs            dict        {label_name: prob} for all classes
    """
    if not model_available():
        return None

    try:
        from scipy.sparse import hstack
        import numpy as np

        clf = _bundle["clf"]
        vw  = _bundle["vw"]
        vc  = _bundle["vc"]
        vs  = _bundle["vs"]
        thresholds = _bundle.get("thresholds", {i: 0.5 for i in range(8)})

        X = hstack([vw.transform([text]),
                    vc.transform([text]),
                    vs.transform([text])])

        probs = clf.predict_proba(X)[0]

        # Apply per-class thresholds (same logic as MACIv4Predictor)
        margins = [probs[i] - thresholds.get(i, 0.5)
                   for i in range(len(probs))]
        pred_label = int(np.argmax(margins))
        pred_conf  = float(probs[pred_label])

        # Authenticity score = probability of class 0
        auth_score = float(probs[0])

        # Top violation (highest prob among violation classes 1-7)
        viol_probs = {i: float(probs[i]) for i in range(1, len(probs))}
        top_viol_id = max(viol_probs, key=viol_probs.get)

        all_probs = {LABEL_NAMES.get(i, str(i)): round(float(p), 3)
                     for i, p in enumerate(probs)}

        return {
            "authenticity_score":  round(auth_score, 3),
            "prediction":          LABEL_NAMES.get(pred_label, "Unknown"),
            "prediction_id":       pred_label,
            "confidence":          round(pred_conf, 3),
            "top_violation":       LABEL_NAMES.get(top_viol_id),
            "top_violation_id":    top_viol_id,
            "top_violation_prob":  round(viol_probs[top_viol_id], 3),
            "requires_review":     0.50 < pred_conf < 0.72,
            "all_probs":           all_probs,
            "model_version":       _bundle.get("macro_f1", "?"),
        }

    except Exception as e:
        print(f"[maci_model] Prediction error: {e}")
        return None
