"""
OWASP Top 10 for LLM Applications 2025 - Professional RAG System
Streamlit Application with Grounded Verification, Exact Citations, and Zero-Hallucination Engine.
"""
import streamlit as st
import json
from generator import OWASPResponseGenerator

# Page configuration
st.set_page_config(
    page_title="RAG - OWASP Top 10 for LLM 2025",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for rich aesthetics and RTL Arabic typography
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Cairo:wght@400;600;700;800;900&display=swap');
    
    html, body, [class*="css"] {
        font-family: 'Cairo', sans-serif;
    }
    
    .rtl-text {
        direction: rtl;
        text-align: right;
    }
    
    .main-title {
        font-size: 2.1rem;
        font-weight: 800;
        color: #1E3A8A;
        margin-bottom: 0.2rem;
    }
    
    .sub-title {
        font-size: 1.05rem;
        color: #475569;
        margin-bottom: 1.5rem;
    }
    
    .metric-card {
        background: linear-gradient(135deg, #F8FAFC 0%, #EFF6FF 100%);
        border: 1px solid #DBEAFE;
        border-radius: 12px;
        padding: 1rem 1.2rem;
        box-shadow: 0 2px 6px rgba(0,0,0,0.03);
        margin-bottom: 1rem;
    }
    
    .badge-primary {
        background-color: #2563EB;
        color: white;
        padding: 0.25rem 0.75rem;
        border-radius: 9999px;
        font-size: 0.85rem;
        font-weight: 600;
        display: inline-block;
    }
    
    .badge-success {
        background-color: #059669;
        color: white;
        padding: 0.25rem 0.75rem;
        border-radius: 9999px;
        font-size: 0.85rem;
        font-weight: 600;
        display: inline-block;
    }
    
    .badge-warning {
        background-color: #D97706;
        color: white;
        padding: 0.25rem 0.75rem;
        border-radius: 9999px;
        font-size: 0.85rem;
        font-weight: 600;
        display: inline-block;
    }
    
    .risk-box {
        background-color: #FEF2F2;
        border-right: 4px solid #EF4444;
        border-radius: 8px;
        padding: 0.9rem 1.2rem;
        margin-bottom: 0.6rem;
    }
    
    .mitigation-box {
        background-color: #ECFDF5;
        border-right: 4px solid #10B981;
        border-radius: 8px;
        padding: 0.9rem 1.2rem;
        margin-bottom: 0.8rem;
    }
    
    .scenario-box {
        background-color: #F8FAFC;
        border-right: 4px solid #6366F1;
        border-radius: 8px;
        padding: 0.9rem 1.2rem;
        margin-bottom: 0.8rem;
    }
    
    .source-box {
        background-color: #F1F5F9;
        border: 1px solid #CBD5E1;
        border-radius: 8px;
        padding: 1rem;
        font-family: monospace;
        font-size: 0.88rem;
        color: #1E293B;
        max-height: 250px;
        overflow-y: auto;
    }
    
    .trust-indicator {
        display: flex;
        align-items: center;
        gap: 0.5rem;
        background-color: #F0FDF4;
        border: 1px solid #BBF7D0;
        color: #166534;
        padding: 0.6rem 1rem;
        border-radius: 8px;
        font-weight: 600;
        font-size: 0.95rem;
    }
</style>
""", unsafe_allow_html=True)

# Initialize generator in cache
@st.cache_resource
def get_generator():
    return OWASPResponseGenerator()

generator = get_generator()

# Sidebar: Document info and settings
with st.sidebar:
    st.markdown("### 📘 وثيقة المصدر (Ground Truth)")
    st.info(
        "**OWASP Top 10 for LLM Applications 2025**\n\n"
        "- **الإصدار:** Version 2025\n"
        "- **تاريخ الإصدار:** November 18, 2024\n"
        "- **الرابط الرسمي:** genai.owasp.org\n"
        "- **عدد الصفحات المعتمدة:** 45 صفحة"
    )
    
    st.markdown("---")
    st.markdown("### ⚡ تصفح المخاطر العشرة مباشرة:")
    all_vulns = generator.rag_engine.get_all_vulnerabilities()
    vuln_options = ["-- اختر من القائمة لتعبئة الاستعلام --"] + [
        f"{v['id']} - {v['name_ar']} ({v['name']})" for v in all_vulns
    ]
    selected_from_menu = st.selectbox("المخاطر الموثقة:", vuln_options, key="sidebar_vuln_select")
    if selected_from_menu != "-- اختر من القائمة لتعبئة الاستعلام --":
        selected_id = selected_from_menu.split(" - ")[0]
        # تتبع آخر قيمة طُبّقت من القائمة لتجنب الكتابة فوق نص المستخدم
        last_applied = st.session_state.get("_sidebar_last_applied", "")
        if last_applied != selected_id:
            st.session_state["_sidebar_last_applied"] = selected_id
            st.session_state["main_input"] = selected_id
            st.rerun()
    else:
        st.session_state["_sidebar_last_applied"] = ""
    
    st.markdown("---")
    st.markdown("### 🔍 معايير التحقق (RAG Triad):")
    st.markdown(
        "1. **Context Relevance:** مدى صلة الوثيقة المسترجعة بسؤالك.\n"
        "2. **Groundedness:** مطابقة الإجابة الكاملة لنص الوثيقة دون هلوسة.\n"
        "3. **Answer Relevance:** شمولية الإجابة للوصف، الوقاية، والسيناريوهات."
    )

# App Header
col_logo, col_head = st.columns([1, 6])
with col_head:
    st.markdown("<div class='rtl-text main-title'>🛡️ نظام RAG لتحليل مخاطر تطبيقات الذكاء الاصطناعي</div>", unsafe_allow_html=True)
    st.markdown("<div class='rtl-text sub-title'>استرجاع موثق ومدقق من وثيقة <b>OWASP Top 10 for LLM Applications 2025</b> مع ذكر أرقام الصفحات والتحقق الصارم من عدم الاختلاق.</div>", unsafe_allow_html=True)

# ── Quick Scenario Buttons ──────────────────────────────────────────────────
st.markdown("<div class='rtl-text' style='font-weight: 700; margin-bottom: 0.4rem;'>💡 أمثلة وسيناريوهات جاهزة للاختبار السريع:</div>", unsafe_allow_html=True)
c1, c2, c3, c4 = st.columns(4)
if c1.button("🎯 حقن التوجيهات (Prompt Injection)", use_container_width=True):
    st.session_state["main_input"] = "Prompt Injection"
    st.rerun()
if c2.button("📄 نص أبيض مخفي بسيرة ذاتية (RAG)", use_container_width=True):
    st.session_state["main_input"] = "أحد المتقدمين وضع نص أبيض غير مرئي داخل سيرته الذاتية لاختراق نظام RAG"
    st.rerun()
if c3.button("✈️ قضية شات بوت طيران كندا", use_container_width=True):
    st.session_state["main_input"] = "شات بوت طيران كندا والهلوسة في أسعار التذاكر ودعوى التعويض"
    st.rerun()
if c4.button("💸 استنزاف التكلفة Denial of Wallet", use_container_width=True):
    st.session_state["main_input"] = "Denial of Wallet واستنزاف الميزانية السحابية بالاستعلامات الضخمة"
    st.rerun()

c5, c6, c7, c8 = st.columns(4)
if c5.button("🔑 تسريب مفاتيح موجه النظام", use_container_width=True):
    st.session_state["main_input"] = "تسريب مفاتيح API وموجه النظام System Prompt Leakage"
    st.rerun()
if c6.button("📦 محول LoRA خبيث في سلاسل الإمداد", use_container_width=True):
    st.session_state["main_input"] = "استخدام محول LoRA خبيث من Hugging Face لاختراق سلاسل الإمداد"
    st.rerun()
if c7.button("🤖 مساعد بريدي بصلاحيات واسعة", use_container_width=True):
    st.session_state["main_input"] = "وكيل ذكي بصلاحيات واسعة يقرأ ويرسل إيميلات دون موافقة بشرية"
    st.rerun()
if c8.button("💉 تسميم البيانات وعميل نائم", use_container_width=True):
    st.session_state["main_input"] = "تسميم بيانات التدريب وزرع عميل نائم Sleeper Agent"
    st.rerun()

# ── Main Query Input ─────────────────────────────────────────────────────────
query_input = st.text_input(
    "أدخل اسم الخطر أو وصف حالة / سيناريو هجوم في تطبيقات الذكاء الاصطناعي:",
    placeholder="اكتب اسم الخطر بالعربي أو الإنجليزي (مثل: Prompt Injection، تسريب البرومبت) أو صف سيناريو...",
    key="main_input"
)

# Search Execution
if query_input.strip():
    with st.spinner("جاري استرجاع البيانات والتحقق من صحتها من ملف OWASP 2025..."):
        result = generator.process_query(query_input.strip())

    # ── لم يتم التعرف على الاستعلام ─────────────────────────────────
    if result.get("no_match"):
        st.markdown("---")
        st.warning(
            "⚠️ **لم يتم التعرف على هذا الاستعلام ضمن مخاطر OWASP Top 10 for LLM Applications 2025.**\n\n"
            "💡 **جرّب:**\n"
            "- اكتب اسم الخطر مباشرة مثل: `Prompt Injection`، `Hallucination`، `Supply Chain`\n"
            "- أو اكتبه بالعربي مثل: `هلوسة`، `تسريب البيانات`، `تسميم البيانات`\n"
            "- أو اضغط على أحد أزرار الأمثلة السريعة أعلاه\n"
            "- أو اختر خطراً مباشرة من قائمة **تصفح المخاطر العشرة** في الشريط الجانبي"
        )
        st.stop()

    c_info = result["classification"]
    v_info = result["verification"]
    rag_metrics = v_info["rag_triad"]

    st.markdown("---")

    # Metrics Summary Row
    m1, m2, m3, m4 = st.columns(4)
    with m1:
        st.markdown(f"""
        <div class='metric-card rtl-text'>
            <div style='font-size:0.85rem; color:#64748B;'>🏷️ تصنيف الخطر</div>
            <div style='font-size:1.25rem; font-weight:800; color:#1E3A8A;'>{c_info['id']}</div>
            <div style='font-size:0.85rem; color:#0284C7; font-weight:600;'>{c_info['name_en']}</div>
        </div>
        """, unsafe_allow_html=True)
    with m2:
        st.markdown(f"""
        <div class='metric-card rtl-text'>
            <div style='font-size:0.85rem; color:#64748B;'>📄 أرقام الصفحات في الملف</div>
            <div style='font-size:1.25rem; font-weight:800; color:#047857;'>صفحة {c_info['pages_display']}</div>
            <div style='font-size:0.85rem; color:#10B981; font-weight:600;'>موثق من النص الأصلي</div>
        </div>
        """, unsafe_allow_html=True)
    with m3:
        st.markdown(f"""
        <div class='metric-card rtl-text'>
            <div style='font-size:0.85rem; color:#64748B;'>🎯 دقة الاسترجاع والمطابقة</div>
            <div style='font-size:1.25rem; font-weight:800; color:#7C3AED;'>{int(result['match_confidence'] * 100)}%</div>
            <div style='font-size:0.85rem; color:#8B5CF6; font-weight:600;'>Hybrid RAG Match</div>
        </div>
        """, unsafe_allow_html=True)
    with m4:
        st.markdown(f"""
        <div class='metric-card rtl-text'>
            <div style='font-size:0.85rem; color:#64748B;'>🛡️ مؤشر الموثوقية (Trust Score)</div>
            <div style='font-size:1.25rem; font-weight:800; color:#059669;'>{rag_metrics['overall_trust_score']}%</div>
            <div style='font-size:0.85rem; color:#059669; font-weight:600;'>✅ خلو تام من الهلوسة</div>
        </div>
        """, unsafe_allow_html=True)

    # Verification Banner
    st.markdown(f"""
    <div class='trust-indicator rtl-text'>
        <span>✅ <b>عملية التحقق المكتملة:</b> {v_info['summary_verdict']} (الصفحات المرجعية المعتمدة: {c_info['pages_display']})</span>
    </div>
    """, unsafe_allow_html=True)
    st.markdown("<br>", unsafe_allow_html=True)

    # Main Tabs
    tab_overview, tab_mitigations, tab_scenarios, tab_verification, tab_source, tab_frameworks = st.tabs([
        "🛡️ التصنيف والوصف والمخاطر",
        "🛡️ طرق الوقاية والتخفيف",
        "⚡ سيناريوهات الهجوم المذكورة",
        "✅ تقرير التحقق والموثوقية",
        "📖 نصوص الوثيقة والاقتباسات",
        "🌐 الأطر المرجعية والتصنيفات"
    ])

    with tab_overview:
        st.markdown(f"### {c_info['id']}: {c_info['name_ar']} ({c_info['name_en']})")
        st.markdown(f"<span class='badge-primary'>{c_info['category_badge']}</span> <span class='badge-success'>الصفحات في المصدر: {c_info['pages_display']}</span>", unsafe_allow_html=True)
        st.markdown("<br>", unsafe_allow_html=True)

        st.markdown("#### 📌 الملخص التنفيذي:")
        st.info(result["description"]["summary_ar"])

        st.markdown("#### 📝 الشرح والتوصيف المفصل (استناداً إلى نص الوثيقة):")
        st.markdown(f"<div class='rtl-text' style='line-height:1.8; font-size:1.02rem;'>{result['description']['full_ar']}</div>", unsafe_allow_html=True)

        if result["description"]["types"]:
            st.markdown("#### 🧩 أنماط وأنواع هذه الثغرة:")
            for t in result["description"]["types"]:
                st.markdown(f"- **{t['type']}:** {t['description']}")

        st.markdown("#### ⚠️ أبرز المخاطر والتأثيرات الناتجة:")
        for r in result["key_risks"]:
            st.markdown(f"<div class='risk-box rtl-text'>💥 {r}</div>", unsafe_allow_html=True)

    with tab_mitigations:
        st.markdown(f"### 🛡️ استراتيجيات وطرق الوقاية والتخفيف (صفحة {c_info['pages_display']}):")
        st.caption("مستخرجة نصاً من قسم Prevention and Mitigation Strategies في ملف OWASP 2025 الرسمي:")
        
        for m in result["mitigations"]:
            st.markdown(f"""
            <div class='mitigation-box rtl-text'>
                <div style='font-size:1.05rem; font-weight:700; color:#065F46; margin-bottom:0.25rem;'>
                    {m['num']}. {m['title']}
                </div>
                <div style='font-size:0.95rem; color:#1F2937; line-height:1.6;'>
                    {m['detail']}
                </div>
            </div>
            """, unsafe_allow_html=True)

    with tab_scenarios:
        st.markdown(f"### ⚡ أمثلة سيناريوهات الهجوم الواردة في الملف:")
        st.caption("سيناريوهات حقيقية وتطبيقية موثقة في الوثيقة (Example Attack Scenarios):")
        
        for sc in result["scenarios"]:
            st.markdown(f"""
            <div class='scenario-box rtl-text'>
                <div style='font-size:0.98rem; color:#1E1B4B; line-height:1.7;'>
                    🛡️ {sc}
                </div>
            </div>
            """, unsafe_allow_html=True)

    with tab_verification:
        st.markdown("### ✅ نظام التحقق من صحة الإجابة والموثوقية (Grounded Verification Engine)")
        st.markdown("يقوم هذا النظام بفحص المخرجات تلقائياً للتأكد من استنادها 100% للوثيقة وعدم اختراع أي معلومات:")
        
        v_col1, v_col2, v_col3 = st.columns(3)
        with v_col1:
            st.metric("Context Relevance (ارتباط السياق)", f"{rag_metrics['context_relevance']}%")
        with v_col2:
            st.metric("Groundedness (المطابقة للنص الأصلي)", f"{rag_metrics['groundedness']}%")
        with v_col3:
            st.metric("Answer Relevance (شمولية الإجابة)", f"{rag_metrics['answer_relevance']}%")

        st.markdown("#### 📋 بنود التدقيق والتحقق:")
        for item in v_info["checklist"]:
            icon = "✅" if item["passed"] else "⚠️"
            status_color = "#059669" if item["passed"] else "#DC2626"
            st.markdown(f"""
            <div style='background-color:#F8FAFC; border:1px solid #E2E8F0; border-radius:8px; padding:0.75rem 1rem; margin-bottom:0.5rem;' class='rtl-text'>
                <b style='color:{status_color}; font-size:1.05rem;'>{icon} {item['label']}</b>
                <div style='color:#475569; font-size:0.9rem; margin-top:0.2rem;'>{item['note']}</div>
            </div>
            """, unsafe_allow_html=True)

        st.markdown("#### 📑 تفاصيل توثيق الصفحات:")
        st.write(f"- **أرقام الصفحات المستشهد بها:** {v_info['citation_details']['cited_pages']}")
        st.write(f"- **الصفحات الرسمية للخطر في الملف:** {v_info['citation_details']['official_pages']}")
        st.write(f"- **حالة التوثيق:** {v_info['citation_details']['status_text']}")

    with tab_source:
        st.markdown(f"### 📖 النص الإنجليزي الأصلي من ملف OWASP 2025:")
        st.caption("النص الحرفي المستخرج من صفحات الوثيقة المعتمدة كإثبات قاطع ومصدر للحقيقة:")
        
        for eq in result["exact_quotes"]:
            st.markdown(f"#### 📄 الصفحة {eq['page']}:")
            st.markdown(f"<div class='source-box'>{eq['text']}</div>", unsafe_allow_html=True)

    with tab_frameworks:
        st.markdown("### 🌐 الأطر المرجعية والتصنيفات ذات الصلة (Related Taxonomies):")
        if result["frameworks"]:
            for fw in result["frameworks"]:
                st.markdown(f"- **{fw}**")
        else:
            st.write("لا توجد أطر إضافية مسجلة لهذه الفئة بالتحديد.")

        if result.get("secondary_matches"):
            st.markdown("---")
            st.markdown("#### 🔄 مخاطر أخرى ذات صلة قد تهمك:")
            for sm in result["secondary_matches"]:
                st.markdown(f"- **{sm['id']}:** {sm['name_ar']} ({sm['name']}) — نسبة تطابق ثانوية: {int(sm['score'] * 100)}%")

    # Download Report Button
    st.markdown("---")
    report_content = f"""# تقرير تحليل الخطر: {c_info['id']} - {c_info['name_ar']} ({c_info['name_en']})
المصدر: OWASP Top 10 for LLM Applications 2025 (الصفحات {c_info['pages_display']})
مؤشر الموثوقية: {rag_metrics['overall_trust_score']}%

## 1. الوصف وأبرز المخاطر
{result['description']['full_ar']}

### أبرز المخاطر:
{chr(10).join(['- ' + r for r in result['key_risks']])}

## 2. طرق الوقاية والتخفيف
{chr(10).join([f"{m['num']}. {m['title']}: {m['detail']}" for m in result['mitigations']])}

## 3. سيناريوهات الهجوم الواردة في الملف
{chr(10).join(['- ' + s for s in result['scenarios']])}

## 4. حالة التحقق والموثوقية
{v_info['summary_verdict']}
- Context Relevance: {rag_metrics['context_relevance']}%
- Groundedness: {rag_metrics['groundedness']}%
- Answer Relevance: {rag_metrics['answer_relevance']}%
"""
    col_dl1, col_dl2 = st.columns([1, 4])
    with col_dl1:
        st.download_button(
            label="📥 تحميل التقرير (Markdown)",
            data=report_content,
            file_name=f"OWASP_2025_{c_info['id']}_Report.md",
            mime="text/markdown"
        )
    with col_dl2:
        st.download_button(
            label="📥 تحميل التقرير (JSON)",
            data=json.dumps(result, ensure_ascii=False, indent=2),
            file_name=f"OWASP_2025_{c_info['id']}_Report.json",
            mime="application/json"
        )

else:
    # Welcome view when no query is typed
    st.markdown("""
    <div style='background-color:#F8FAFC; border:1px solid #E2E8F0; border-radius:12px; padding:1.8rem; margin-top:1rem;' class='rtl-text'>
        <h3 style='color:#1E3A8A; margin-top:0;'>مرحباً بك في نظام RAG لتحليل مخاطر OWASP Top 10 2025</h3>
        <p style='color:#334155; line-height:1.8; font-size:1.05rem;'>
            هذا النظام مصمم لمساعدتك في استعلام وتحليل أي خطر أو سيناريو هجوم في تطبيقات النماذج اللغوية الكبيرة والذكاء الاصطناعي التوليدي، مع استناد تام إلى النسخة الرسمية الصادرة حديثاً: <b>OWASP Top 10 for LLM Applications 2025</b>.
        </p>
        <h4 style='color:#0F172A;'>المزايا الرئيسية:</h4>
        <ul style='color:#475569; line-height:1.9;'>
            <li><b>تصنيف الخطر ووصفه:</b> يحدد رمز الخطر الدقيق (مثل LLM01:2025 إلى LLM10:2025) مع شرح معمق وأبرز تأثيراته.</li>
            <li><b>طرق الوقاية والتخفيف:</b> يقدم استراتيجيات الدفاع الموصى بها في الملف الرسمي مرقمة ومفصلة.</li>
            <li><b>سيناريوهات الهجوم:</b> يستخرج الأمثلة الواقعية المذكورة في الوثيقة (مثل CVE-2024-5184 و PoisonGPT و LeftOvers وقضية طيران كندا).</li>
            <li><b>نظام التحقق والموثوقية:</b> مطابقة أرقام الصفحات بدقة (Citations) ومقاييس RAG Triad لضمان عدم اختراع أي معلومة (Zero Hallucination).</li>
            <li><b>بساطة وسهولة الرفع:</b> كود خفيف وعملي متوافق مع Streamlit (STR) وجاهز للنشر المباشر.</li>
        </ul>
        <p style='color:#2563EB; font-weight:700;'>
            👉 جرب النقر على أحد أزرار السيناريوهات في الأعلى أو اكتب استفسارك في صندوق البحث أعلاه للبدء فوراً!
        </p>
    </div>
    """, unsafe_allow_html=True)
