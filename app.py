"""
暗号資産・Web3・投資案件 詐欺/ポンジ調査ツール（拡張版）
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

# ── CSS ──────────────────────────────────────────────────────────

st.markdown("""
<style>
.risk-card {
    padding: 12px 16px;
    border-radius: 8px;
    margin: 6px 0;
    font-size: 14px;
}
.risk-high { background: #3d1414; border-left: 4px solid #ff4444; }
.risk-medium { background: #3d2e0a; border-left: 4px solid #ff9900; }
.risk-low { background: #0d2d1a; border-left: 4px solid #00cc66; }
.risk-unknown { background: #1e1e2e; border-left: 4px solid #888888; }
.signal-box {
    background: #1a1a2e;
    border: 1px solid #333;
    border-radius: 6px;
    padding: 10px 14px;
    margin: 4px 0;
}
.quote { color: #aaa; font-style: italic; font-size: 13px; }
.type-badge {
    display: inline-block;
    background: #2a1f4a;
    border: 1px solid #6644aa;
    border-radius: 12px;
    padding: 3px 10px;
    margin: 3px;
    font-size: 13px;
    color: #cc99ff;
}
.score-label { font-size: 12px; color: #888; margin-top: 4px; }
.never-item { color: #ff6666; padding: 3px 0; }
</style>
""", unsafe_allow_html=True)

st.title("🔍 暗号資産・Web3 詐欺/ポンジ調査ツール")
st.caption("⚠️ このツールは**投資助言ではありません**。リスク調査の補助目的です。最終判断は必ずご自身で行ってください。")
st.divider()

# ── 入力フォーム ──────────────────────────────────────────────────

with st.form("investigation_form"):
    st.subheader("📥 調査対象の入力")
    col1, col2 = st.columns(2)

    with col1:
        project_name = st.text_input("プロジェクト名・サービス名", placeholder="例: XYZ Finance, AbcToken")
        url_input = st.text_input("URL（公式サイト・ホワイトペーパー等）", placeholder="例: https://example.com")
        contract_address = st.text_input("コントラクトアドレス（EVM/Solana）", placeholder="例: 0x1234...abcd")
        chain_hint = st.selectbox("チェーン（コントラクト調査用）",
            ["auto", "ethereum", "bsc", "polygon", "arbitrum", "optimism", "avalanche", "base", "solana"])

    with col2:
        text_input = st.text_area("テキスト貼り付け（資料・説明文・メッセージ等）", height=180,
            placeholder="ホワイトペーパーの内容、紹介文、チャットのメッセージなどをここに貼り付けてください")
        pdf_file = st.file_uploader("PDF アップロード", type=["pdf"],
            help="ホワイトペーパー・提案資料・契約書等")

    submitted = st.form_submit_button("🔍 調査開始", type="primary", use_container_width=True)

# ── 調査実行 ──────────────────────────────────────────────────────

if submitted:
    if not any([project_name, url_input, contract_address, text_input, pdf_file]):
        st.error("少なくとも1つの入力を提供してください。")
        st.stop()

    combined_text = text_input or ""
    domain_for_analysis = ""
    reputation_results = None

    # PDF抽出
    if pdf_file:
        with st.spinner("📄 PDF を解析中..."):
            pdf_text, pdf_error = extract_pdf_text(pdf_file.read())
            if pdf_error:
                st.warning(f"PDF: {pdf_error}")
            else:
                combined_text = combined_text + "\n\n" + pdf_text
                st.success(f"✅ PDF から {len(pdf_text):,} 文字を抽出しました")

    # URLコンテンツ取得
    if url_input:
        with st.spinner("🌐 サイトを取得中..."):
            web_result = fetch_url_content(url_input)
            if web_result["error"]:
                st.warning(f"サイト取得: {web_result['error']}")
            else:
                combined_text = combined_text + "\n\n" + web_result["text"]
                st.success(f"✅ サイト取得完了（タイトル: {web_result['title'][:60]}）")
            import re
            m = re.search(r"(?:https?://)?([a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,})", url_input)
            if m:
                domain_for_analysis = m.group(1)

    # テキスト分析
    text_signals, text_score = [], 0
    financial_claims, company_info = [], {}
    case_types, external_claims = [], []
    reward_structure, revenue_map = {}, {}

    if combined_text.strip():
        with st.spinner("🔎 テキストを分析中..."):
            text_signals, text_score = analyze_text(combined_text)
            financial_claims = extract_financial_claims(combined_text)
            company_info = extract_company_info(combined_text)
            case_types = classify_case_types(text_signals)
            external_claims = extract_claims(combined_text)
            reward_structure = analyze_reward_structure(combined_text)
            revenue_map = analyze_revenue_source(combined_text, text_signals)

    # ドメイン調査
    domain_result = {"risks": [], "score": 0}
    if domain_for_analysis:
        with st.spinner("🌐 ドメイン調査中..."):
            domain_result = analyze_domain(domain_for_analysis)
            wb = check_wayback_machine(domain_for_analysis)
            if wb.get("available") and wb.get("first_snapshot"):
                domain_result["wayback_first"] = wb["first_snapshot"]

    # 評判検索
    reputation_score = 0
    if project_name:
        with st.spinner(f"🔍 評判を検索中..."):
            reputation_results = search_scam_reputation(project_name)
            if not reputation_results.get("error"):
                mentions = reputation_results.get("scam_mentions", 0)
                reputation_score = 25 if mentions >= 5 else 15 if mentions >= 3 else 8 if mentions >= 1 else 0

    # コントラクト調査
    contract_result = {"risks": [], "score": 0, "holder_info": {}, "error": None}
    if contract_address.strip():
        with st.spinner("⛓️ コントラクトを調査中..."):
            chain = chain_hint if chain_hint != "auto" else ""
            contract_result = analyze_contract(contract_address.strip(), chain)
            if contract_result.get("error"):
                st.warning(f"コントラクト: {contract_result['error']}")

    # スコア集計
    total_score = calculate_final_score(
        text_score, contract_result.get("score", 0),
        domain_result.get("score", 0), reputation_score,
    )
    verdict, verdict_color, ponzi_likelihood = build_verdict(total_score)
    high_signals = [s.category for s in text_signals if s.severity == "high"]
    medium_signals = [s.category for s in text_signals if s.severity == "medium"]
    dangerous_contract = [r.flag for r in contract_result.get("risks", []) if r.is_dangerous]
    high_signals.extend(dangerous_contract[:3])
    structural_risks = build_structural_risks(
        text_signals, contract_result.get("risks", []),
        domain_result.get("score", 0), reputation_score
    )
    questions = generate_questions(text_signals, bool(contract_address.strip()))
    conclusion = generate_conclusion(total_score, high_signals, ponzi_likelihood)

    # ────────────────────────────────────────────────────────────
    # 出力レポート
    # ────────────────────────────────────────────────────────────

    st.divider()
    st.header("📊 調査レポート")
    st.caption(f"生成日時: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} ／ 対象: {project_name or url_input or contract_address}")

    # ── 1. 総合判定 ───────────────────────────────────────────────
    if verdict_color in ("darkred", "red"):
        st.error(f"## 総合判定: {verdict}")
    elif verdict_color == "orange":
        st.warning(f"## 総合判定: {verdict}")
    elif verdict_color == "yellow":
        st.warning(f"## 総合判定: {verdict}")
    else:
        st.success(f"## 総合判定: {verdict}")

    # ── 2. リスクスコア ───────────────────────────────────────────
    col_s1, col_s2, col_s3 = st.columns(3)
    with col_s1:
        st.metric("リスクスコア", f"{total_score} / 100")
        st.progress(total_score / 100)
        st.markdown('<div class="score-label">⬆️ 高いほど危険（0=低リスク / 100=最高危険）</div>', unsafe_allow_html=True)
    with col_s2:
        st.metric("詐欺/ポンジ疑いの強さ", ponzi_likelihood)
    with col_s3:
        score_label = (
            "参加非推奨" if total_score >= 81 else
            "非常に危険" if total_score >= 61 else
            "高リスク" if total_score >= 41 else
            "要注意" if total_score >= 21 else "低リスク"
        )
        st.metric("スコア区分", score_label)
        st.caption("0〜20: 低リスク ／ 21〜40: 要注意 ／ 41〜60: 高リスク ／ 61〜80: 非常に危険 ／ 81〜100: 参加非推奨")

    st.divider()

    # ── 3. 案件タイプ分類 ─────────────────────────────────────────
    st.subheader("🏷️ 案件タイプ分類")
    if case_types:
        html = "".join(f'<span class="type-badge">{t}</span>' for t in case_types)
        st.markdown(html, unsafe_allow_html=True)
    else:
        st.info("テキスト未入力のため分類不可")

    # ── 4. 主な危険シグナル ───────────────────────────────────────
    st.subheader("🚨 主な危険シグナル")
    if text_signals:
        for sig in sorted(text_signals, key=lambda s: s.score, reverse=True):
            icon = "⛔" if sig.severity == "high" else "⚠️"
            color_cls = "risk-high" if sig.severity == "high" else "risk-medium"
            html = f"""<div class="risk-card {color_cls}">
                {icon} <strong>{sig.category}</strong> (+{sig.score}点)<br>
                <span class="quote">検出: 「{sig.matched}」</span><br>
                <small style="color:#bbb">{sig.reason}</small>
            </div>"""
            st.markdown(html, unsafe_allow_html=True)
    elif combined_text:
        st.success("重大な危険シグナルは検出されませんでした")
    else:
        st.info("テキスト未入力")

    if dangerous_contract:
        st.error(f"⛓️ コントラクト危険シグナル: {' / '.join(dangerous_contract)}")

    # ── 5. 構造別リスク ───────────────────────────────────────────
    st.subheader("📐 構造別リスク")
    cols = st.columns(3)
    for i, sr in enumerate(structural_risks):
        color_cls = {"high": "risk-high", "medium": "risk-medium", "low": "risk-low", "unknown": "risk-unknown"}.get(sr.level, "risk-unknown")
        level_label = {"high": "🔴 高", "medium": "🟡 中", "low": "🟢 低", "unknown": "⚪ 不明"}.get(sr.level, "⚪")
        html = f"""<div class="risk-card {color_cls}">
            <strong>{sr.name}</strong><br>
            {level_label}<br>
            <small style="color:#bbb">{sr.detail}</small>
        </div>"""
        with cols[i % 3]:
            st.markdown(html, unsafe_allow_html=True)

    # ── 6. 価格期待・上場煽り ─────────────────────────────────────
    st.subheader("📈 価格期待・上場煽り")
    listing_signals = [s for s in text_signals if s.category in ["上場価格・将来価格の断定", "成功銘柄比較・倍率煽り"]]
    if listing_signals or financial_claims:
        for s in listing_signals:
            st.error(f"⛔ {s.category}: 「{s.matched}」")
            st.caption(s.reason)
        if financial_claims:
            st.markdown("**検出された数値表現:**")
            for c in financial_claims[:10]:
                st.code(c)
    else:
        st.success("価格断定・倍率煽りの表現は検出されませんでした")

    # ── 7. 報酬構造の分析 ────────────────────────────────────────
    st.subheader("💰 報酬構造の分析")
    if reward_structure:
        for rtype, items in reward_structure.items():
            with st.expander(f"**{rtype}** ({len(items)}件検出)", expanded=True):
                for item in items[:5]:
                    st.markdown(f'<div class="signal-box"><span class="quote">{item}</span></div>', unsafe_allow_html=True)
    elif combined_text:
        st.success("特定の報酬構造は検出されませんでした")
    else:
        st.info("テキスト未入力")

    # ── 8. 収益原資マップ ────────────────────────────────────────
    st.subheader("🗺️ 収益原資マップ")
    if revenue_map:
        for key, val in revenue_map.items():
            color = "🔴" if "疑い" in val or "可能性" in val or "依存" in val else "⚪"
            st.markdown(f"**{key}**: {color} {val}")
    else:
        st.info("テキスト未入力のため分析不可")

    # ── 9. 出金リスク ────────────────────────────────────────────
    st.subheader("💸 出金リスク")
    withdrawal_signals = [s for s in text_signals if "出金" in s.category or "税金" in s.category]
    honeypot = any(r.flag == "ハニーポット" and r.is_dangerous for r in contract_result.get("risks", []))
    high_tax = [r for r in contract_result.get("risks", []) if "Tax" in r.flag and r.is_dangerous]

    if "出金前の税金・手数料要求" in {s.category for s in text_signals}:
        st.error("⛔ 出金前に税金・手数料の入金を求める表現が検出されました。これは詐欺の最終段階の典型手口です。絶対に支払わないでください。")
    if honeypot:
        st.error("⛔ ハニーポット検出: このトークンは購入後に売却不能になる可能性があります")
    for t in high_tax:
        st.error(f"⛔ {t.flag}: {t.description}")
    for s in withdrawal_signals:
        if s.category != "出金前の税金・手数料要求":
            st.warning(f"⚠️ {s.category}: 「{s.matched}」")
    if not withdrawal_signals and not honeypot and not high_tax:
        st.success("出金制限に関する直接シグナルは検出されませんでした（実際の出金条件は別途確認が必要）")

    # ── 10. トークン/オンチェーンリスク ─────────────────────────
    st.subheader("⛓️ トークン/オンチェーンリスク")
    if contract_address.strip() and not contract_result.get("error"):
        holder_info = contract_result.get("holder_info", {})
        if holder_info:
            c1, c2 = st.columns(2)
            with c1:
                st.metric("トークン名", f"{holder_info.get('token_name', '不明')} ({holder_info.get('token_symbol', '?')})")
            with c2:
                st.metric("保有者数", holder_info.get("holder_count", "不明"))

        dangerous = [r for r in contract_result.get("risks", []) if r.is_dangerous]
        safe = [r for r in contract_result.get("risks", []) if not r.is_dangerous]

        if dangerous:
            st.error(f"危険なコントラクト機能が {len(dangerous)} 件検出されました")
            for r in dangerous:
                st.markdown(f'<div class="risk-card risk-high">⛔ <strong>{r.flag}</strong><br><small style="color:#bbb">{r.description}</small></div>', unsafe_allow_html=True)
        else:
            st.success("重大なコントラクトリスクは検出されませんでした")

        if safe:
            with st.expander("✅ 正常確認済み項目"):
                for r in safe:
                    st.markdown(f"✅ {r.flag}")

        if holder_info.get("top_holders"):
            conc = holder_info.get("top10_concentration", "不明")
            is_risky = holder_info.get("concentration_risk", False)
            if is_risky:
                st.warning(f"⚠️ 上位10アドレスで **{conc}** を保有（集中リスク高）")
            else:
                st.info(f"上位10アドレスの保有比率: {conc}")
    elif contract_address.strip():
        st.warning(f"コントラクト調査: {contract_result.get('error', '不明')}")
    else:
        st.info("コントラクトアドレスが入力されていません")

    # ── 11. チーム/会社実体リスク ─────────────────────────────────
    st.subheader("🏢 チーム/会社実体リスク")
    if company_info:
        for k, v in company_info.items():
            label = {"company": "会社名", "representative": "代表者", "address": "所在地", "emails": "メール"}.get(k, k)
            st.markdown(f"- **{label}**: {v}")
        st.caption("※ 自動抽出のため正確性は保証されません。一次情報で必ず確認してください。")
    elif combined_text:
        st.warning("⚠️ テキスト内に会社・運営者情報を確認できませんでした（匿名運営の可能性）")
    else:
        st.info("テキスト未入力")

    # ── 12. ドメイン/サイト調査 ──────────────────────────────────
    st.subheader("🌐 ドメイン/サイト調査")
    if domain_for_analysis:
        c1, c2 = st.columns(2)
        with c1:
            if domain_result.get("creation_date"):
                age = domain_result.get("age_days", 0)
                st.markdown(f"- **ドメイン**: {domain_result['domain']}")
                st.markdown(f"- **作成日**: {domain_result['creation_date']} （{age}日前）")
                st.markdown(f"- **登録者**: {domain_result.get('registrar', '不明')}")
        with c2:
            if domain_result.get("wayback_first"):
                ts = domain_result["wayback_first"]
                st.markdown(f"- **最古スナップショット**: {ts[:4]}年{ts[4:6]}月")
        for risk in domain_result.get("risks", []):
            st.warning(f"⚠️ {risk}")
        if not domain_result.get("risks") and domain_result.get("creation_date"):
            st.success("ドメインに関する重大リスクは検出されませんでした")
        if domain_result.get("error"):
            st.info(f"WHOIS: {domain_result['error']}")
    else:
        st.info("URLが入力されていないためスキップしました")

    # ── 13. 外部確認が必要な主張 ─────────────────────────────────
    st.subheader("🔎 外部確認が必要な主張")
    if external_claims:
        st.warning(f"以下の {len(external_claims)} 件の主張について、外部での公式確認が必要です")
        confirmed = []
        unconfirmed = [c for c in external_claims]

        st.markdown("**⚠️ 未確認（要検証）:**")
        for c in unconfirmed[:15]:
            st.markdown(f'<div class="signal-box">📌 <strong>{c["label"]}</strong>: <span class="quote">{c["text"]}</span></div>', unsafe_allow_html=True)
    elif combined_text:
        st.success("特定の未確認主張は検出されませんでした")
    else:
        st.info("テキスト未入力")

    # ── 14. 法規制リスク ─────────────────────────────────────────
    st.subheader("⚖️ 法規制リスク")
    jp_risky = any(s.category in ["元本保証", "固定利回り/日利/月利/自動複利", "MLM/チーム報酬/ランク制度"] for s in text_signals)
    if jp_risky:
        st.warning(
            "元本保証・固定利回り・紹介報酬が組み合わさる場合、以下の法律に抵触する可能性があります（参考情報）:\n"
            "- **金融商品取引法**: 元本保証・利回り保証の禁止\n"
            "- **特定商取引法**: 連鎖販売取引（マルチ）の規制\n"
            "- **出資法**: 高利回りの利息制限\n\n"
            "※ 海外・DeFiプロジェクトは日本で未登録のものが多いため金融庁登録の有無だけで詐欺とは判定しません。"
        )
    else:
        st.info(
            "明確な法規制抵触表現は検出されませんでした。\n"
            "ただし金融庁登録の有無・各国規制は別途確認してください。\n"
            "[金融庁警告リスト](https://www.fsa.go.jp/ordinary/kanyu/20050912.html) ／ "
            "[FTC](https://www.ftc.gov/scams) ／ [SEC](https://www.sec.gov/tcr)"
        )

    # ── 評判検索 ─────────────────────────────────────────────────
    if reputation_results and not reputation_results.get("error"):
        mentions = reputation_results.get("scam_mentions", 0)
        with st.expander(f"🔍 評判検索結果（詐欺関連ヒット: {mentions}件）"):
            if mentions > 0:
                st.error(f"詐欺・問題に関連するウェブ情報が {mentions}件 検出されました")
            for r in reputation_results.get("results", []):
                icon = "⛔" if r.get("is_scam_related") else "ℹ️"
                st.markdown(f"{icon} **{r['title']}**")
                st.caption(r['snippet'])
                st.markdown(f"[{r['url'][:80]}]({r['url']})")
                st.divider()

    # ── スコア内訳 ────────────────────────────────────────────────
    with st.expander("📊 スコア内訳"):
        st.markdown(f"| カテゴリ | スコア |")
        st.markdown(f"|---|---|")
        st.markdown(f"| テキスト分析 | +{text_score} |")
        st.markdown(f"| コントラクト | +{contract_result.get('score', 0)} |")
        st.markdown(f"| ドメイン | +{domain_result.get('score', 0)} |")
        st.markdown(f"| 評判検索 | +{reputation_score} |")
        st.markdown(f"| **合計（上限100）** | **{total_score}** |")

    # ── 15. 相手に確認すべき質問テンプレ ─────────────────────────
    st.subheader("❓ 相手に送る質問テンプレ")
    st.caption("以下の質問をコピーして相手に送り、回答と証拠を確認してください。")
    questions_text = "\n".join(f"Q{i}. {q}" for i, q in enumerate(questions, 1))
    st.text_area("質問テンプレ（コピー用）", questions_text, height=220)

    # ── 16. 絶対にやってはいけない行動 ──────────────────────────
    if total_score >= 41:
        st.subheader("🚫 絶対にやってはいけない行動")
        st.error("このプロジェクトは高リスクと判定されました。以下の行動は絶対に避けてください。")
        never_list = [
            "生活資金・貯金を入れない",
            "借金して参加しない",
            "追加送金しない（出金できないと言われても）",
            "出金のための保証金・税金・手数料を払わない",
            "友人・家族を紹介しない",
            "秘密鍵・シードフレーズを誰にも渡さない",
            "ウォレット接続を安易にしない",
            "運営者不明のアプリ・拡張機能をインストールしない",
            "少額テスト前に大金を入れない",
            "「もうすぐ出金できる」という言葉を信じて追加入金しない",
        ]
        for item in never_list:
            st.markdown(f'<div class="never-item">🚫 {item}</div>', unsafe_allow_html=True)

    # ── 17. 最終結論 ──────────────────────────────────────────────
    st.divider()
    st.subheader("📌 最終結論")
    if total_score >= 61:
        st.error(conclusion)
    elif total_score >= 41:
        st.error(conclusion)
    elif total_score >= 21:
        st.warning(conclusion)
    else:
        st.info(conclusion)

    # ── 18. 免責文 ────────────────────────────────────────────────
    st.divider()
    st.caption(
        "⚠️ **免責事項**: このレポートは自動分析による参考情報です。"
        "**投資助言ではありません。** 最終判断は必ずご自身で行い、必要に応じて専門家にご相談ください。"
        "スコアが低くても投資リスクがゼロであることを意味しません。"
        "詐欺被害に遭った場合は警察（#9110）・金融庁・消費者センター（188）にご相談ください。"
    )
