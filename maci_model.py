"""
maci_model.py — MACI v4 Model Loader
Loads model from a PRIVATE HuggingFace repo at runtime.
Model weights never touch GitHub.
"""

import os
import pickle
from pathlib import Path
from typing import Dict, Optional

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

_bundle = None
_loaded = False


def _try_load() -> bool:
    global _bundle, _loaded

    # ── Priority 1: local models/ folder (SageMaker / local dev) ──────
    for local_path in ["models/ml_model.pkl", "maci_v4_models/ml_model.pkl"]:
        if Path(local_path).exists():
            try:
                with open(local_path, "rb") as f:
                    _bundle = pickle.load(f)
                _loaded = True
                return True
            except Exception as e:
                print(f"[maci_model] Local load failed: {e}")

    # ── Priority 2: HuggingFace private repo (Streamlit Cloud) ────────
    hf_token = os.environ.get("HF_TOKEN") or os.environ.get("HUGGINGFACE_TOKEN")
    hf_repo  = os.environ.get("HF_REPO_ID")

    if hf_token and hf_repo:
        try:
            from huggingface_hub import hf_hub_download
            path = hf_hub_download(
                repo_id=hf_repo,
                filename="ml_model.pkl",
                token=hf_token,
                repo_type="model",
            )
            with open(path, "rb") as f:
                _bundle = pickle.load(f)
            _loaded = True
            return True
        except Exception as e:
            print(f"[maci_model] HuggingFace load failed: {e}")

    return False


def model_available() -> bool:
    if _loaded:
        return True
    return _try_load()


def predict_authenticity(text: str) -> Optional[Dict]:
    if not model_available():
        return None

    try:
        from scipy.sparse import hstack
        import numpy as np

        clf        = _bundle["clf"]
        vw         = _bundle["vw"]
        vc         = _bundle["vc"]
        vs         = _bundle["vs"]
        thresholds = _bundle.get("thresholds", {i: 0.5 for i in range(8)})

        X      = hstack([vw.transform([text]),
                         vc.transform([text]),
                         vs.transform([text])])
        probs  = clf.predict_proba(X)[0]
        margins = [probs[i] - thresholds.get(i, 0.5) for i in range(len(probs))]
        pred_label = int(np.argmax(margins))
        pred_conf  = float(probs[pred_label])
        auth_score = float(probs[0])

        viol_probs  = {i: float(probs[i]) for i in range(1, len(probs))}
        top_viol_id = max(viol_probs, key=viol_probs.get)
        all_probs   = {LABEL_NAMES.get(i, str(i)): round(float(p), 3)
                       for i, p in enumerate(probs)}

        return {
            "authenticity_score": round(auth_score, 3),
            "prediction":         LABEL_NAMES.get(pred_label, "Unknown"),
            "prediction_id":      pred_label,
            "confidence":         round(pred_conf, 3),
            "top_violation":      LABEL_NAMES.get(top_viol_id),
            "top_violation_id":   top_viol_id,
            "top_violation_prob": round(viol_probs[top_viol_id], 3),
            "requires_review":    0.50 < pred_conf < 0.72,
            "all_probs":          all_probs,
        }

    except Exception as e:
        print(f"[maci_model] Prediction error: {e}")
        return None
