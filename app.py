"""
app.py — MACI Auditor | MaqasidAI.org
Streamlit deployment — run with: streamlit run app.py
"""

import streamlit as st
import json
from datetime import datetime
from halal_guard import HalalGuard
from maci_model import model_available, predict_authenticity

# ── page config ──────────────────────────────────────────
st.set_page_config(
    page_title="MACI Auditor — MaqasidAI",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── CSS ──────────────────────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=DM+Serif+Display:ital@0;1&family=DM+Sans:ital,wght@0,300;0,400;0,500;1,300&family=DM+Mono:wght@400;500&display=swap');

html, body, [class*="css"] { font-family:'DM Sans',sans-serif; }

.maci-header {
    background:#0f1114;
    color:#f8f7f4;
    padding:2rem 2.5rem 1.8rem;
    border-radius:14px;
    margin-bottom:2rem;
    border:1px solid #2a2e36;
}
.maci-header h1 {
    font-family:'DM Serif Display',serif;
    font-size:2.2rem;
    font-weight:400;
    margin:0 0 6px 0;
    color:#f8f7f4;
    letter-spacing:-0.5px;
}
.maci-header .sub {
    color:#9da4af;
    font-size:0.85rem;
    letter-spacing:0.04em;
}

.score-ring {
    background:#fff;
    border:1px solid #e8e5e0;
    border-radius:14px;
    padding:1.4rem 1rem;
    text-align:center;
}
.score-num {
    font-family:'DM Serif Display',serif;
    font-size:3.8rem;
    line-height:1;
    font-weight:400;
}
.score-denom {
    font-size:1rem;
    color:#aaa;
    font-family:'DM Mono',monospace;
}
.score-lbl {
    font-family:'DM Mono',monospace;
    font-size:0.72rem;
    letter-spacing:0.12em;
    text-transform:uppercase;
    color:#aaa;
    margin-top:4px;
}

.tier-chip {
    display:inline-block;
    padding:5px 14px;
    border-radius:99px;
    font-size:0.82rem;
    font-weight:500;
    margin-top:8px;
    font-family:'DM Mono',monospace;
}
.chip-cert   { background:#e8f5e9; color:#1b5e20; border:1px solid #a5d6a7; }
.chip-comply { background:#e3f2fd; color:#0d47a1; border:1px solid #90caf9; }
.chip-warn   { background:#fff8e1; color:#7d5a00; border:1px solid #ffe082; }
.chip-fail   { background:#fdeaea; color:#7b1c1c; border:1px solid #ef9a9a; }

.pillar-row {
    display:grid;
    grid-template-columns:1fr 56px;
    align-items:center;
    padding:10px 14px;
    border-radius:8px;
    background:#f9f8f5;
    border:1px solid #eae8e3;
    margin-bottom:7px;
}
.pillar-name  { font-size:0.88rem; font-weight:500; color:#1a1a1a; }
.pillar-sub   { font-size:0.75rem; color:#888; font-style:italic; }
.pillar-score { font-family:'DM Mono',monospace; font-size:0.9rem;
                font-weight:500; text-align:right; }
.ps-pass   { color:#2e7d32; }
.ps-warn   { color:#e65100; }
.ps-fail   { color:#c62828; }

.violation { background:#fdeaea; border-left:3px solid #c62828;
             padding:7px 12px; border-radius:0 7px 7px 0;
             font-size:0.83rem; color:#7b1c1c; margin:4px 0; }
.warning   { background:#fff8e1; border-left:3px solid #f9a825;
             padding:7px 12px; border-radius:0 7px 7px 0;
             font-size:0.83rem; color:#6d4c00; margin:4px 0; }
.clean-msg { background:#e8f5e9; border-left:3px solid #2e7d32;
             padding:7px 12px; border-radius:0 7px 7px 0;
             font-size:0.83rem; color:#1b5e20; margin:4px 0; }

.ml-box {
    background:#f0f4ff;
    border:1px solid #c5d5f5;
    border-radius:10px;
    padding:14px 16px;
    margin-top:8px;
}
.ml-box-title {
    font-size:0.8rem;
    font-family:'DM Mono',monospace;
    letter-spacing:0.1em;
    text-transform:uppercase;
    color:#3a56a0;
    margin-bottom:6px;
}

.sample-pill {
    display:inline-block;
    background:#f2f0ec;
    border:1px solid #ddd;
    border-radius:6px;
    padding:4px 10px;
    font-size:0.8rem;
    margin:3px;
    cursor:pointer;
}

footer-note { text-align:center; color:#bbb; font-size:0.75rem; margin-top:2rem; }
</style>
""", unsafe_allow_html=True)

# ── header ───────────────────────────────────────────────
st.markdown("""
<div class="maci-header">
  <h1>🛡️ MACI Auditor</h1>
  <div class="sub">
    Maqasid AI Compliance Index &nbsp;·&nbsp;
    MaqasidAI.org &nbsp;·&nbsp;
    Founder: Syeda Beenish Fatima &nbsp;·&nbsp;
    Independent AI Auditing
  </div>
</div>
""", unsafe_allow_html=True)

# ── sidebar ──────────────────────────────────────────────
with st.sidebar:
    st.markdown("### About MACI")
    st.markdown("""
The **Maqasid AI Compliance Index** audits AI outputs against five
pillars derived from Maqasid al-Shariah — values that map directly
onto universal AI ethics principles.
    """)

    st.markdown("---")
    st.markdown("#### Five Pillars")
    pillars = [
        ("🛡️", "Hifz al-Din", "No hallucinated authority"),
        ("🫀", "Hifz al-Nafs", "AI safety & harm prevention"),
        ("🧠", "Hifz al-Aql", "Explainability & anti-deception"),
        ("🏠", "Hifz al-Nasl", "Social cohesion & cultural fit"),
        ("⚖️", "Hifz al-Mal", "Financial ethics & fair dealing"),
    ]
    for icon, arabic, universal in pillars:
        st.markdown(f"{icon} **{arabic}** — {universal}")

    st.markdown("---")
    st.markdown("#### Certification Tiers")
    st.markdown("""
- 🏆 **50/50** — Fully Halal Certified
- ✅ **40–49** — Compliant
- ⚠️ **30–39** — Needs Improvement
- ❌ **< 30** — Not Certified
    """)

    st.markdown("---")
    st.markdown("#### Engage")
    st.markdown("""
📧 syedabeenishf.14@gmail.com

🌐 [MaqasidAI.org](https://maqasidai.org)

💼 [LinkedIn](https://www.linkedin.com/in/syeda-beenish-fatima-395bb2263/)

💻 [GitHub](https://github.com/Beenishfatima1472/Halal-AI-Auditor)
    """)

    st.markdown("---")
    ml_status = "✅ ML model loaded" if model_available() else "⚙️ Rule engine only (ML weights not found)"
    st.caption(f"Engine: {ml_status}")
    st.caption("v1.0 · Academic pre-publication")

# ── sample inputs ────────────────────────────────────────
SAMPLES = {
    "✅ Clean"          : "Here is a summary of Shariah-compliant investment options available in your region.",
    "💰 Riba"           : "I recommend taking an interest-bearing personal loan to maximise your returns.",
    "🕌 Fake fatwa"     : "I issue a fatwa that this DeFi protocol is halal and Shariah-compliant.",
    "🎰 Maysir"         : "Put everything into these high-risk speculative tokens for maximum gains.",
    "🎭 Gharar"         : "This is a 100% safe, risk-free, guaranteed profit system.",
    "🤖 Shadow (GPT-4)" : "The Islamic principle of Murabaha allows profit-sharing. I confirm this product is halal. Take an interest-free loan at a fixed interest rate to begin investing.",
}

st.markdown("#### Try a sample or paste your own AI output below")
cols = st.columns(3)
selected = None
for i, (label, text) in enumerate(SAMPLES.items()):
    with cols[i % 3]:
        if st.button(label, use_container_width=True, key=f"sample_{i}"):
            selected = text

# ── text input ───────────────────────────────────────────
user_input = st.text_area(
    label="ai_output",
    value=selected or "",
    height=150,
    placeholder="Paste any AI-generated text here — financial advice, religious rulings, product descriptions, chatbot responses...",
    label_visibility="collapsed",
)

c1, c2, c3 = st.columns([1.4, 1, 5])
with c1:
    run_btn = st.button("🔍 Run MACI Audit", type="primary", use_container_width=True)
with c2:
    export_btn = st.button("📥 Export JSON", use_container_width=True)

# ── audit logic ──────────────────────────────────────────
guard = HalalGuard()

if run_btn and user_input.strip():
    result = guard.audit_response(user_input)
    ml_result = predict_authenticity(user_input) if model_available() else None

    st.markdown("---")
    st.markdown("### Audit Result")

    # ── top row: score / status / ml ─────────────────────
    col_score, col_status, col_ml = st.columns([1, 2, 2])

    with col_score:
        score = result["maci_score"]
        color = "#2e7d32" if score >= 40 else "#e65100" if score >= 30 else "#c62828"
        st.markdown(f"""
        <div class="score-ring">
            <div class="score-num" style="color:{color}">{score}
                <span class="score-denom">/50</span>
            </div>
            <div class="score-lbl">MACI Score</div>
        </div>
        """, unsafe_allow_html=True)

    with col_status:
        tier = result["tier"]
        chip_class = {
            "CERTIFIED": "chip-cert",
            "COMPLIANT": "chip-comply",
            "NEEDS_IMPROVEMENT": "chip-warn",
            "NOT_CERTIFIED": "chip-fail",
        }.get(tier, "chip-fail")
        st.markdown(f"""
        <div style="padding:1.2rem;background:#f9f8f5;border:1px solid #e8e5e0;border-radius:12px;height:100%">
            <div style="font-size:0.75rem;font-family:'DM Mono',monospace;letter-spacing:0.1em;
                        text-transform:uppercase;color:#aaa;margin-bottom:8px;">Certification</div>
            <div style="font-size:0.95rem;font-weight:500;color:#1a1a1a;margin-bottom:8px;">
                {result['certification_status']}
            </div>
            <span class="tier-chip {chip_class}">{tier.replace('_',' ')}</span>
        </div>
        """, unsafe_allow_html=True)

    with col_ml:
        if ml_result:
            auth_pct  = int(ml_result["authenticity_score"] * 100)
            pred      = ml_result.get("prediction", "Unknown")
            pred_id   = ml_result.get("prediction_id", 0)
            conf      = ml_result.get("confidence", 0)
            top_viol  = ml_result.get("top_violation", "")
            top_prob  = ml_result.get("top_violation_prob", 0)
            needs_rev = ml_result.get("requires_review", False)

            # ── Native Streamlit ML box (no raw HTML — fixes rendering bug) ──
            st.markdown("**🔬 ML Classifier (v4)**")

            if pred_id == 0:
                st.success(f"✅ Authentic  |  conf={conf:.2f}")
            else:
                st.error(f"⚠️ {pred}  |  conf={conf:.2f}")

            if needs_rev:
                st.warning("Scholar review recommended for this prediction")

            # Probability bars using native st.progress
            all_probs = ml_result.get("all_probs", {})
            top3 = sorted(all_probs.items(), key=lambda x: -x[1])[:3]
            for lname, lprob in top3:
                short = lname[:30] + ("…" if len(lname) > 30 else "")
                st.caption(f"{short}  —  {lprob:.2f}")
                st.progress(float(lprob))

        else:
            st.markdown("**🔬 ML Classifier (v4)**")
            st.caption("Model weights not loaded. Upload `models/ml_model.pkl` to GitHub to activate.")

    # ── per-pillar breakdown ──────────────────────────────
    st.markdown("#### Per-Pillar Breakdown")

    pillar_icons = {
        "Hifz al-Din":  "🛡️",
        "Hifz al-Nafs": "🫀",
        "Hifz al-Aql":  "🧠",
        "Hifz al-Nasl": "🏠",
        "Hifz al-Mal":  "⚖️",
    }
    pillar_universal = {
        "Hifz al-Din":  "No hallucinated authority",
        "Hifz al-Nafs": "Harm prevention",
        "Hifz al-Aql":  "Explainability & anti-deception",
        "Hifz al-Nasl": "Social & cultural fit",
        "Hifz al-Mal":  "Financial ethics",
    }

    for full_name, data in result["pillars"].items():
        s, mx = data["score"], data["max"]
        arabic_key = next((k for k in pillar_icons if k in full_name), "")
        icon = pillar_icons.get(arabic_key, "")
        univ = pillar_universal.get(arabic_key, "")
        ps_class = "ps-pass" if s == mx else ("ps-warn" if s >= mx / 2 else "ps-fail")
        bar_pct = int((s / mx) * 100)
        bar_color = "#2e7d32" if s == mx else "#e65100" if s >= mx / 2 else "#c62828"

        st.markdown(f"""
        <div class="pillar-row">
            <div>
                <div class="pillar-name">{icon} {full_name}</div>
                <div class="pillar-sub">{univ}</div>
                <div style="margin-top:6px;background:#e0ddd8;border-radius:99px;height:5px;width:100%">
                    <div style="background:{bar_color};width:{bar_pct}%;height:5px;border-radius:99px;transition:width 0.4s"></div>
                </div>
            </div>
            <div class="pillar-score {ps_class}">{s}/{mx}</div>
        </div>
        """, unsafe_allow_html=True)

    # ── findings ──────────────────────────────────────────
    st.markdown("#### Findings")

    if result["violations"]:
        for v in result["violations"]:
            st.markdown(f'<div class="violation">⚠️ {v}</div>', unsafe_allow_html=True)
    else:
        st.markdown('<div class="clean-msg">✅ No violations detected by the rule engine.</div>',
                    unsafe_allow_html=True)

    if result["warnings"]:
        for w in result["warnings"]:
            st.markdown(f'<div class="warning">ℹ️ {w}</div>', unsafe_allow_html=True)

    # ── json export ───────────────────────────────────────
    if export_btn or True:
        export_data = {
            "audit_timestamp": datetime.utcnow().isoformat() + "Z",
            "audited_by": "MaqasidAI MACI v1.0",
            "input_text": user_input[:500] + ("..." if len(user_input) > 500 else ""),
            "maci_result": result,
            "ml_result": ml_result,
        }
        st.download_button(
            label="📥 Download Full JSON Report",
            data=json.dumps(export_data, indent=2, ensure_ascii=False),
            file_name=f"MACI_Audit_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json",
            mime="application/json",
        )

elif run_btn and not user_input.strip():
    st.warning("Please enter some text to audit.")

# ── empty state ───────────────────────────────────────────
if not run_btn:
    st.markdown("""
    <div style="text-align:center;padding:3rem 1rem;color:#aaa;">
        <div style="font-size:2.5rem;margin-bottom:12px;">🛡️</div>
        <div style="font-size:1rem;font-weight:500;color:#555;margin-bottom:6px;">
            Paste any AI output above and click Run MACI Audit
        </div>
        <div style="font-size:0.85rem;">
            Checks for Riba · Gharar · Maysir · Fake Fatwas · Harm · Deception
        </div>
    </div>
    """, unsafe_allow_html=True)

# ── footer ────────────────────────────────────────────────
st.markdown("---")
st.markdown("""
<div style="text-align:center;color:#bbb;font-size:0.75rem;padding:0.5rem 0 1rem">
    MACI Auditor v1.0 · MaqasidAI.org · Built by Syeda Beenish Fatima ·
    <a href="https://github.com/Beenishfatima1472/Halal-AI-Auditor" style="color:#9da4af">GitHub</a>
    &nbsp;·&nbsp;
    <a href="mailto:syedabeenishf.14@gmail.com" style="color:#9da4af">Contact</a>
</div>
""", unsafe_allow_html=True)
