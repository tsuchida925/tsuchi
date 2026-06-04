"""
暗号資産・Web3・投資案件 詐欺/ポンジ調査ツール（わかりやすいレポート版）
※ このツールは投資助言ではありません。最終判断はご自身で行ってください。
"""

import streamlit as st
from datetime import datetime

from analyzer.text_analyzer import (
    analyze_text, extract_financial_claims, extract_company_info,
    classify_case_types, extract_claims, analyze_reward_structure,
    analyze_revenue_source, generate_questions,
)
from analyzer.contract_analyzer import analyze_contract
from analyzer.domain_analyzer import analyze_domain
from analyzer.web_analyzer import fetch_url_content, search_scam_reputation, check_wayback_machine
from analyzer.pdf_analyzer import extract_pdf_text
from analyzer.pptx_analyzer import extract_pptx_text
from analyzer.scoring import (
    calculate_final_score, build_verdict, build_structural_risks,
    generate_conclusion,
)

# ── ページ設定 ────────────────────────────────────────────────────

st.set_page_config(
    page_title="詐欺・ポンジ調査ツール",
    page_icon="🔍",
    layout="wide",
)

st.markdown("""
<style>
/* 全体 */
.block-container { padding-top: 2rem; }

/* 総合判定バナー */
.verdict-banner {
    text-align: center;
    padding: 28px 20px;
    border-radius: 16px;
    margin-bottom: 20px;
}
.verdict-danger  { background: linear-gradient(135deg,#4a0000,#7a0000); border: 2px solid #ff3333; }
.verdict-warning { background: linear-gradient(135deg,#3a2000,#5a3500); border: 2px solid #ff8800; }
.verdict-caution { background: linear-gradient(135deg,#3a3400,#4a4200); border: 2px solid #cccc00; }
.verdict-safe    { background: linear-gradient(135deg,#003a1a,#005a28); border: 2px solid #00cc55; }
.verdict-title { font-size: 2rem; font-weight: bold; margin: 0; }
.verdict-sub   { font-size: 1rem; color: #ddd; margin-top: 6px; }

/* スコアメーター */
.score-meter {
    text-align: center;
    padding: 16px;
    background: #1a1a2e;
    border-radius: 12px;
}
.score-number { font-size: 3rem; font-weight: bold; line-height: 1; }
.score-label  { font-size: 0.8rem; color: #888; margin-top: 4px; }

/* 専門家カード */
.expert-card {
    background: #1e1e30;
    border-radius: 12px;
    padding: 16px;
    margin: 8px 0;
    border-left: 5px solid #555;
}
.expert-card.danger  { border-left-color: #ff3333; }
.expert-card.warning { border-left-color: #ff8800; }
.expert-card.safe    { border-left-color: #00cc55; }
.expert-card.unknown { border-left-color: #888888; }
.expert-name    { font-size: 0.85rem; color: #aaa; margin-bottom: 4px; }
.expert-verdict { font-size: 1rem; font-weight: bold; }
.expert-detail  { font-size: 0.85rem; color: #bbb; margin-top: 6px; line-height: 1.5; }

/* シグナルリスト */
.signal-item {
    display: flex;
    align-items: flex-start;
    gap: 10px;
    padding: 10px 14px;
    background: #1a1a2e;
    border-radius: 8px;
    margin: 5px 0;
}
.signal-icon { font-size: 1.3rem; flex-shrink: 0; }
.signal-text { flex: 1; }
.signal-title { font-weight: bold; font-size: 0.95rem; }
.signal-reason { font-size: 0.82rem; color: #bbb; margin-top: 3px; }
.signal-quote { font-size: 0.8rem; color: #888; font-style: italic; margin-top: 2px; }

/* 絶対NG */
.never-box {
    background: #2a0a0a;
    border: 2px solid #cc0000;
    border-radius: 12px;
    padding: 16px 20px;
    margin: 10px 0;
}
.never-item { color: #ff8888; padding: 4px 0; font-size: 0.95rem; }

/* 質問テンプレ */
.q-item {
    background: #1a2030;
    border-left: 3px solid #4488ff;
    padding: 8px 12px;
    margin: 5px 0;
    border-radius: 0 8px 8px 0;
    font-size: 0.9rem;
}

/* タイプバッジ */
.type-badges { display: flex; flex-wrap: wrap; gap: 6px; margin: 8px 0; }
.type-badge {
    background: #2a1f4a;
    border: 1px solid #6644aa;
    border-radius: 16px;
    padding: 4px 12px;
    font-size: 0.82rem;
    color: #cc99ff;
}
</style>
""", unsafe_allow_html=True)

# ── ヘッダー ─────────────────────────────────────────────────────

st.title("🔍 暗号資産・Web3 詐欺/ポンジ調査ツール")
st.caption("⚠️ このツールは**投資助言ではありません**。リスク調査の補助目的です。最終判断は必ずご自身で行ってください。")
st.divider()

# ── 入力フォーム ──────────────────────────────────────────────────

with st.form("investigation_form"):
    st.subheader("📥 調査対象の入力")
    col1, col2 = st.columns(2)
    with col1:
        project_name = st.text_input("プロジェクト名・サービス名", placeholder="例: XYZ Finance, AbcToken")
        url_input    = st.text_input("URL（公式サイト・ホワイトペーパー等）", placeholder="例: https://example.com")
        contract_address = st.text_input("コントラクトアドレス（EVM/Solana）", placeholder="例: 0x1234...abcd")
        chain_hint   = st.selectbox("チェーン（コントラクト調査用）",
            ["auto","ethereum","bsc","polygon","arbitrum","optimism","avalanche","base","solana"])
    with col2:
        text_input = st.text_area("テキスト貼り付け（資料・説明文・メッセージ等）", height=180,
            placeholder="ホワイトペーパーの内容、紹介文、チャットのメッセージなどをここに貼り付けてください")
        uploaded_file = st.file_uploader(
            "PDF / PPTX アップロード",
            type=["pdf", "pptx"],
            help="ホワイトペーパー・提案資料・スライド資料など",
        )

    submitted = st.form_submit_button("🔍 調査開始", type="primary", use_container_width=True)

# ── 調査実行 ──────────────────────────────────────────────────────

if submitted:
    if not any([project_name, url_input, contract_address, text_input, uploaded_file]):
        st.error("少なくとも1つの入力を提供してください。")
        st.stop()

    combined_text = text_input or ""
    domain_for_analysis = ""
    reputation_results  = None

    if uploaded_file:
        fname = uploaded_file.name.lower()
        if fname.endswith(".pptx"):
            with st.spinner("📊 PPTX を解析中..."):
                pptx_text, pptx_error = extract_pptx_text(uploaded_file.read())
                if pptx_error:
                    st.warning(f"PPTX: {pptx_error}")
                else:
                    combined_text += "\n\n" + pptx_text
                    st.success(f"✅ PPTX から {len(pptx_text):,} 文字を抽出しました")
        else:
            with st.spinner("📄 PDF を解析中..."):
                pdf_text, pdf_error = extract_pdf_text(uploaded_file.read())
                if pdf_error:
                    st.warning(f"PDF: {pdf_error}")
                else:
                    combined_text += "\n\n" + pdf_text
                    st.success(f"✅ PDF から {len(pdf_text):,} 文字を抽出しました")

    if url_input:
        with st.spinner("🌐 サイトを取得中..."):
            web_result = fetch_url_content(url_input)
            if not web_result["error"]:
                combined_text += "\n\n" + web_result["text"]
                st.success(f"✅ サイト取得完了（{web_result['title'][:50]}）")
            import re
            m = re.search(r"(?:https?://)?([a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,})", url_input)
            if m:
                domain_for_analysis = m.group(1)

    text_signals, text_score = [], 0
    financial_claims = []
    company_info     = {}
    case_types       = []
    external_claims  = []
    reward_structure = {}
    revenue_map      = {}

    if combined_text.strip():
        with st.spinner("🔎 テキストを分析中..."):
            text_signals, text_score = analyze_text(combined_text)
            financial_claims  = extract_financial_claims(combined_text)
            company_info      = extract_company_info(combined_text)
            case_types        = classify_case_types(text_signals)
            external_claims   = extract_claims(combined_text)
            reward_structure  = analyze_reward_structure(combined_text)
            revenue_map       = analyze_revenue_source(combined_text, text_signals)

    domain_result = {"risks": [], "score": 0}
    if domain_for_analysis:
        with st.spinner("🌐 ドメイン調査中..."):
            domain_result = analyze_domain(domain_for_analysis)
            wb = check_wayback_machine(domain_for_analysis)
            if wb.get("available") and wb.get("first_snapshot"):
                domain_result["wayback_first"] = wb["first_snapshot"]

    reputation_score = 0
    if project_name:
        with st.spinner(f"🔍 評判を検索中..."):
            reputation_results = search_scam_reputation(project_name)
            if not reputation_results.get("error"):
                m = reputation_results.get("scam_mentions", 0)
                reputation_score = 25 if m >= 5 else 15 if m >= 3 else 8 if m >= 1 else 0

    contract_result = {"risks": [], "score": 0, "holder_info": {}, "error": None}
    if contract_address.strip():
        with st.spinner("⛓️ コントラクトを調査中..."):
            ch = chain_hint if chain_hint != "auto" else ""
            contract_result = analyze_contract(contract_address.strip(), ch)

    total_score = calculate_final_score(
        text_score, contract_result.get("score", 0),
        domain_result.get("score", 0), reputation_score,
    )
    verdict, verdict_color, ponzi_likelihood = build_verdict(total_score)
    high_signals = [s.category for s in text_signals if s.severity == "high"]
    dangerous_contract = [r.flag for r in contract_result.get("risks", []) if r.is_dangerous]
    high_signals.extend(dangerous_contract[:3])
    structural_risks = build_structural_risks(
        text_signals, contract_result.get("risks", []),
        domain_result.get("score", 0), reputation_score,
    )
    questions  = generate_questions(text_signals, bool(contract_address.strip()))
    conclusion = generate_conclusion(total_score, high_signals, ponzi_likelihood)

    # ════════════════════════════════════════════════════════════
    # ★ シンプルレポート（メイン表示）
    # ════════════════════════════════════════════════════════════

    st.divider()
    st.markdown(f"**📋 調査レポート** ／ {datetime.now().strftime('%Y-%m-%d %H:%M')} ／ 対象: {project_name or url_input or contract_address or '（入力なし）'}")

    # ── 総合判定バナー ──────────────────────────────────────────
    vc_cls = {
        "darkred": "danger", "red": "danger",
        "orange": "warning", "yellow": "caution", "green": "safe"
    }.get(verdict_color, "warning")

    score_color = (
        "#ff3333" if total_score >= 61 else
        "#ff8800" if total_score >= 41 else
        "#cccc00" if total_score >= 21 else "#00cc55"
    )

    # 一言コメント
    one_liner = (
        "この案件には重大な危険シグナルが複数あります。参加は非推奨です。" if total_score >= 81 else
        "複数の危険シグナルが確認されています。慎重な確認が必要です。"   if total_score >= 61 else
        "いくつかリスクが見つかりました。追加確認をしてから判断してください。" if total_score >= 41 else
        "目立ったリスクは少ないですが、投資には常にリスクがあります。"   if total_score >= 21 else
        "現時点で重大なリスクシグナルは少ないです。ただし過信は禁物です。"
    )

    st.markdown(f"""
    <div class="verdict-banner verdict-{vc_cls}">
      <div class="verdict-title">{verdict}</div>
      <div class="verdict-sub">{one_liner}</div>
    </div>
    """, unsafe_allow_html=True)

    # ── スコアと案件タイプ ──────────────────────────────────────
    col_sc, col_ty = st.columns([1, 2])
    with col_sc:
        st.markdown(f"""
        <div class="score-meter">
          <div class="score-number" style="color:{score_color}">{total_score}</div>
          <div style="color:#888;font-size:1rem">/ 100</div>
          <div class="score-label">リスクスコア（高いほど危険）</div>
        </div>
        """, unsafe_allow_html=True)

    with col_ty:
        st.markdown("**この案件に含まれる要素**")
        if case_types:
            badges = "".join(f'<span class="type-badge">{t}</span>' for t in case_types)
            st.markdown(f'<div class="type-badges">{badges}</div>', unsafe_allow_html=True)
        else:
            st.caption("テキスト未入力のため分類不可")

    st.markdown("")

    # ── 専門家チームからの意見 ──────────────────────────────────
    st.subheader("👥 専門家チームからの意見")

    # 各専門家の判定を構成
    def expert_card(icon, name, role, verdict_text, detail, level="unknown"):
        cls = {"high":"danger","medium":"warning","low":"safe","unknown":"unknown"}.get(level,"unknown")
        return f"""
        <div class="expert-card {cls}">
          <div class="expert-name">{icon} {name}｜{role}</div>
          <div class="expert-verdict">{verdict_text}</div>
          <div class="expert-detail">{detail}</div>
        </div>"""

    cats = {s.category for s in text_signals}

    # 1. 財務アドバイザー
    if "固定利回り/日利/月利/自動複利" in cats or "元本保証" in cats:
        fa_level, fa_v = "high", "⚠️ 収益の仕組みに重大な疑問があります"
        fa_d = "日利・月利・元本保証は、投資の世界では「ありえない約束」です。通常の金融商品でこのような保証はできません。収益がどこから来るのか、明確な説明を求めてください。"
    elif any(s.score > 0 for s in text_signals):
        fa_level, fa_v = "medium", "⚠️ 収益の説明が不十分です"
        fa_d = "収益の原資（お金がどこから来るか）が明確でありません。参加前に具体的な説明を求めてください。"
    else:
        fa_level, fa_v = "unknown", "💬 収益構造の情報が不十分です"
        fa_d = "テキスト情報が少ないため詳細な分析ができません。ホワイトペーパーや説明資料の入力をお試しください。"
    st.markdown(expert_card("💰","財務アドバイザー","収益・利回りの分析",fa_v,fa_d,fa_level), unsafe_allow_html=True)

    # 2. 法律の専門家
    jp_risky = any(s.category in ["元本保証","固定利回り/日利/月利/自動複利","MLM/チーム報酬/ランク制度"] for s in text_signals)
    if jp_risky:
        la_level, la_v = "medium", "⚠️ 日本の法律に抵触する可能性があります"
        la_d = "元本保証・固定利回り・紹介報酬の組み合わせは、日本の金融商品取引法・特定商取引法に抵触する可能性があります。※海外案件はグレーゾーンの場合もあります。"
    else:
        la_level, la_v = "low", "✅ 明確な法律違反表現は検出されませんでした"
        la_d = "ただし、金融庁への登録状況や各国の規制については別途確認が必要です。"
    st.markdown(expert_card("⚖️","法律の専門家","法規制・コンプライアンスの分析",la_v,la_d,la_level), unsafe_allow_html=True)

    # 3. セキュリティエンジニア
    dangerous_ct = [r for r in contract_result.get("risks",[]) if r.is_dangerous]
    honeypot = any(r.flag == "ハニーポット" for r in dangerous_ct)
    if honeypot:
        se_level, se_v = "high", "⛔ 購入後に売れなくなる罠が検出されました（ハニーポット）"
        se_d = "このトークンは買えても売れない「ハニーポット」の可能性があります。資金を入れると取り出せなくなるリスクがあります。"
    elif dangerous_ct:
        se_level, se_v = "high", f"⚠️ コントラクトに {len(dangerous_ct)} 件の危険な設定があります"
        se_d = "運営者がトークンを無制限に発行できる・特定のウォレットをブロックできるなど、ユーザーに不利な設定が見つかりました。"
    elif contract_address.strip():
        se_level, se_v = "low", "✅ コントラクトに重大なリスクは検出されませんでした"
        se_d = "主要なセキュリティチェックをクリアしています。ただし100%安全を保証するものではありません。"
    else:
        se_level, se_v = "unknown", "💬 コントラクトアドレスが入力されていません"
        se_d = "トークンのコントラクトアドレスを入力すると、より詳細な安全性チェックができます。"
    st.markdown(expert_card("🔐","セキュリティエンジニア","コントラクト・技術的リスクの分析",se_v,se_d,se_level), unsafe_allow_html=True)

    # 4. 調査員
    no_company = not company_info
    has_investor_claim = "投資家・財団・提携先による信用補強" in cats
    if "出金前の税金・手数料要求" in cats:
        inv_level, inv_v = "high", "⛔ 出金前に追加入金を求める手口が検出されました"
        inv_d = "「出金するには税金・手数料を先払いしてください」という要求は、詐欺の最終段階でよく使われる手口です。絶対に支払わないでください。"
    elif no_company and has_investor_claim:
        inv_level, inv_v = "high", "⚠️ 運営者が不明なのに有名投資家を主張しています"
        inv_d = "投資家・財団の名前が出ていますが、運営者・会社情報が確認できません。有名な名前を使って信用を偽装する手口の可能性があります。"
    elif no_company:
        inv_level, inv_v = "medium", "⚠️ 運営者・会社情報が確認できませんでした"
        inv_d = "誰が運営しているのかが不明です。問題が起きたときに連絡・責任追及ができない可能性があります。"
    elif has_investor_claim:
        inv_level, inv_v = "medium", "💬 投資家・提携先の外部確認が必要です"
        inv_d = "投資家や財団の名前が出ていますが、その会社の公式サイトや発表でも確認できるか調べてください。"
    else:
        inv_level, inv_v = "low", "✅ 運営者情報の記載が確認されました"
        inv_d = "会社・担当者情報の記載があります。実際に実在するか外部でも確認することをお勧めします。"
    st.markdown(expert_card("🕵️","調査員","運営実体・信頼性の分析",inv_v,inv_d,inv_level), unsafe_allow_html=True)

    # 5. 出金・資金回収の専門家
    if reputation_score >= 15:
        out_level, out_v = "high", f"⚠️ 「出金できない」「詐欺」という口コミが {reputation_results.get('scam_mentions',0)} 件見つかりました"
        out_d = "インターネット上にこのプロジェクトに関する警告や被害報告がある可能性があります。参加前に十分な調査をしてください。"
    elif "出金ロック・制限" in cats:
        out_level, out_v = "medium", "⚠️ 出金に制限・条件がある可能性があります"
        out_d = "自由にいつでも全額出金できるか確認してください。ロック期間・条件・手数料の詳細を事前に確認することが重要です。"
    else:
        out_level, out_v = "unknown", "💬 出金条件の詳細が確認できませんでした"
        out_d = "「いつでも全額出金できますか？」「過去の出金実績（TxID）を見せてください」と相手に直接確認することをお勧めします。"
    st.markdown(expert_card("💸","出金・資金回収の専門家","出金リスクの分析",out_v,out_d,out_level), unsafe_allow_html=True)

    # ── 見つかった危険なポイント（平易な言葉で）──────────────────
    if text_signals or dangerous_ct:
        st.markdown("")
        st.subheader("🚨 見つかった危険なポイント")

        plain_signals = sorted(text_signals, key=lambda s: s.score, reverse=True)
        for sig in plain_signals[:8]:
            icon = "⛔" if sig.severity == "high" else "⚠️"
            st.markdown(f"""
            <div class="signal-item">
              <div class="signal-icon">{icon}</div>
              <div class="signal-text">
                <div class="signal-title">{sig.category}</div>
                <div class="signal-reason">{sig.reason}</div>
                <div class="signal-quote">検出された表現: 「{sig.matched}」</div>
              </div>
            </div>""", unsafe_allow_html=True)

        for r in dangerous_ct[:4]:
            st.markdown(f"""
            <div class="signal-item">
              <div class="signal-icon">⛔</div>
              <div class="signal-text">
                <div class="signal-title">⛓️ {r.flag}</div>
                <div class="signal-reason">{r.description}</div>
              </div>
            </div>""", unsafe_allow_html=True)

    # ── 絶対にやってはいけないこと（高リスク時）──────────────────
    if total_score >= 41:
        st.markdown("")
        st.subheader("🚫 絶対にやってはいけないこと")
        never_items = [
            "生活費・貯金を入れない",
            "借金して参加しない",
            "「もうすぐ出金できる」と言われても追加入金しない",
            "出金前に税金・保証金・手数料を払わない",
            "友人・家族を紹介しない",
            "秘密鍵・シードフレーズを誰にも渡さない",
            "運営者不明のアプリをインストールしない",
            "ウォレットを安易に接続しない",
        ]
        items_html = "".join(f'<div class="never-item">🚫 {i}</div>' for i in never_items)
        st.markdown(f'<div class="never-box">{items_html}</div>', unsafe_allow_html=True)

    # ── 相手に確認すべき質問 ─────────────────────────────────────
    st.markdown("")
    st.subheader("❓ 参加前に相手に聞くべきこと")
    st.caption("以下の質問を相手に送り、証拠つきで回答してもらってください。答えられない・曖昧な場合は危険サインです。")
    for i, q in enumerate(questions[:8], 1):
        st.markdown(f'<div class="q-item"><strong>Q{i}.</strong> {q}</div>', unsafe_allow_html=True)

    # ── 最終結論 ──────────────────────────────────────────────────
    st.markdown("")
    st.subheader("📌 最終結論")
    if total_score >= 61:
        st.error(f"**{conclusion}**")
    elif total_score >= 41:
        st.error(conclusion)
    elif total_score >= 21:
        st.warning(conclusion)
    else:
        st.info(conclusion)

    # ════════════════════════════════════════════════════════════
    # ★ 詳細レポート（折りたたみ）
    # ════════════════════════════════════════════════════════════

    st.divider()
    st.markdown("### 📂 詳細レポート（専門家向け）")
    st.caption("より詳しい情報は以下の各セクションを開いてご確認ください。")

    # 案件タイプ詳細
    with st.expander("🏷️ 案件タイプ分類の詳細"):
        if case_types:
            for t in case_types:
                st.markdown(f"- {t}")
        else:
            st.info("テキスト未入力")

    # 報酬構造
    with st.expander("💰 報酬構造の詳細分析"):
        if reward_structure:
            for rtype, items in reward_structure.items():
                st.markdown(f"**{rtype}**")
                for item in items[:5]:
                    st.markdown(f"> {item}")
        else:
            st.info("報酬構造の記載は検出されませんでした")

    # 収益原資マップ
    with st.expander("🗺️ 収益原資マップ"):
        if revenue_map:
            for k, v in revenue_map.items():
                color = "🔴" if any(w in v for w in ["疑い","可能性","依存","不明"]) else "✅"
                st.markdown(f"**{k}**: {color} {v}")
        else:
            st.info("テキスト未入力のため分析不可")

    # 外部確認が必要な主張
    with st.expander(f"🔎 外部確認が必要な主張（{len(external_claims)}件）"):
        if external_claims:
            for c in external_claims[:15]:
                st.markdown(f"📌 **{c['label']}**: `{c['text']}`")
        else:
            st.info("特定の未確認主張は検出されませんでした")

    # コントラクト詳細
    with st.expander("⛓️ コントラクト/オンチェーン詳細"):
        if contract_address.strip() and not contract_result.get("error"):
            h = contract_result.get("holder_info", {})
            if h:
                st.markdown(f"**トークン**: {h.get('token_name','不明')} ({h.get('token_symbol','?')})  ／  保有者数: {h.get('holder_count','不明')}")
            all_risks = contract_result.get("risks", [])
            dangerous = [r for r in all_risks if r.is_dangerous]
            safe      = [r for r in all_risks if not r.is_dangerous]
            if dangerous:
                st.error(f"危険項目 {len(dangerous)} 件")
                for r in dangerous:
                    st.markdown(f"- ⛔ **{r.flag}**: {r.description}")
            if safe:
                st.success(f"正常項目 {len(safe)} 件")
                for r in safe:
                    st.markdown(f"- ✅ {r.flag}")
            if h.get("top_holders"):
                st.markdown(f"**上位10保有者の集中度**: {h.get('top10_concentration','不明')}")
                for holder in h["top_holders"][:5]:
                    st.markdown(f"- `{holder['address']}` {holder['percent']} {holder.get('tag','')}")
        elif contract_result.get("error"):
            st.warning(contract_result["error"])
        else:
            st.info("コントラクトアドレスが入力されていません")

    # ドメイン調査
    with st.expander("🌐 ドメイン/サイト調査の詳細"):
        if domain_for_analysis:
            if domain_result.get("creation_date"):
                st.markdown(f"- **ドメイン**: {domain_result['domain']}")
                st.markdown(f"- **作成日**: {domain_result['creation_date']} ({domain_result.get('age_days',0)}日前)")
                st.markdown(f"- **登録者**: {domain_result.get('registrar','不明')}")
            if domain_result.get("wayback_first"):
                ts = domain_result["wayback_first"]
                st.markdown(f"- **最古アーカイブ**: {ts[:4]}年{ts[4:6]}月")
            for r in domain_result.get("risks", []):
                st.warning(f"⚠️ {r}")
            if not domain_result.get("risks") and domain_result.get("creation_date"):
                st.success("ドメインに関する重大リスクは検出されませんでした")
        else:
            st.info("URLが入力されていません")

    # 評判検索
    with st.expander(f"🔍 評判・口コミ検索結果"):
        if reputation_results and not reputation_results.get("error"):
            mentions = reputation_results.get("scam_mentions", 0)
            if mentions > 0:
                st.error(f"詐欺・問題関連の情報が {mentions} 件検出されました")
            for r in reputation_results.get("results", [])[:8]:
                icon = "⛔" if r.get("is_scam_related") else "ℹ️"
                st.markdown(f"{icon} **{r['title']}**")
                st.caption(r["snippet"])
                st.markdown(f"[リンク]({r['url']})")
                st.divider()
        elif reputation_results and reputation_results.get("error"):
            st.warning(reputation_results["error"])
        else:
            st.info("プロジェクト名が入力されていません")

    # スコア内訳
    with st.expander("📊 スコア内訳"):
        st.markdown("| カテゴリ | スコア |")
        st.markdown("|---|---|")
        st.markdown(f"| テキスト分析 | +{text_score} |")
        st.markdown(f"| コントラクト | +{contract_result.get('score',0)} |")
        st.markdown(f"| ドメイン     | +{domain_result.get('score',0)} |")
        st.markdown(f"| 評判検索     | +{reputation_score} |")
        st.markdown(f"| **合計（上限100）** | **{total_score}** |")
        st.caption("0〜20: 低リスク ／ 21〜40: 要注意 ／ 41〜60: 高リスク ／ 61〜80: 非常に危険 ／ 81〜100: 参加非推奨")

    # ── 免責文 ────────────────────────────────────────────────────
    st.divider()
    st.caption(
        "⚠️ **免責事項**: このレポートは自動分析による参考情報です。**投資助言ではありません。** "
        "最終判断は必ずご自身で行い、必要に応じて専門家にご相談ください。"
        "スコアが低くても投資リスクがゼロであることを意味しません。"
        "詐欺被害に遭った場合は警察（#9110）・金融庁・消費者センター（188）にご相談ください。"
    )
