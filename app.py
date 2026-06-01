"""
暗号資産・Web3・投資案件 詐欺/ポンジ調査ツール
※ このツールは投資助言ではありません。最終判断はご自身で行ってください。
"""

import streamlit as st
from datetime import datetime

from analyzer.text_analyzer import analyze_text, extract_financial_claims, extract_company_info
from analyzer.contract_analyzer import analyze_contract, CHAIN_IDS
from analyzer.domain_analyzer import analyze_domain
from analyzer.web_analyzer import fetch_url_content, search_scam_reputation, check_wayback_machine
from analyzer.pdf_analyzer import extract_pdf_text
from analyzer.scoring import (
    calculate_final_score, build_verdict, generate_questions,
    generate_conclusion, RiskReport
)

# ── ページ設定 ────────────────────────────────────────────────────

st.set_page_config(
    page_title="詐欺・ポンジ調査ツール",
    page_icon="🔍",
    layout="wide",
)

st.title("🔍 暗号資産・Web3 詐欺/ポンジ調査ツール")
st.caption("⚠️ このツールは**投資助言ではありません**。リスク調査の補助目的です。最終判断はご自身で行ってください。")
st.divider()

# ── 入力フォーム ──────────────────────────────────────────────────

with st.form("investigation_form"):
    st.subheader("📥 調査対象の入力")

    col1, col2 = st.columns(2)

    with col1:
        project_name = st.text_input(
            "プロジェクト名・サービス名",
            placeholder="例: XYZ Finance, AbcToken",
        )
        url_input = st.text_input(
            "URL（公式サイト・ホワイトペーパー等）",
            placeholder="例: https://example.com",
        )
        contract_address = st.text_input(
            "コントラクトアドレス（EVM/Solana）",
            placeholder="例: 0x1234...abcd",
        )
        chain_hint = st.selectbox(
            "チェーン（コントラクト調査用）",
            ["auto", "ethereum", "bsc", "polygon", "arbitrum", "optimism", "avalanche", "base", "solana"],
        )

    with col2:
        text_input = st.text_area(
            "テキスト貼り付け（資料・説明文・メッセージ等）",
            height=150,
            placeholder="ホワイトペーパーの内容、紹介文、チャットのメッセージなどをここに貼り付けてください",
        )
        pdf_file = st.file_uploader(
            "PDF アップロード",
            type=["pdf"],
            help="ホワイトペーパー・提案資料・契約書等",
        )

    submitted = st.form_submit_button("🔍 調査開始", type="primary", use_container_width=True)

# ── 調査実行 ──────────────────────────────────────────────────────

if submitted:
    has_any_input = any([project_name, url_input, contract_address, text_input, pdf_file])
    if not has_any_input:
        st.error("少なくとも1つの入力を提供してください。")
        st.stop()

    combined_text = text_input or ""
    domain_for_analysis = ""
    reputation_results = None

    # ── ステップ1: PDF抽出 ────────────────────────────────────────
    if pdf_file:
        with st.spinner("📄 PDF を解析中..."):
            pdf_text, pdf_error = extract_pdf_text(pdf_file.read())
            if pdf_error:
                st.warning(f"PDF: {pdf_error}")
            else:
                combined_text = combined_text + "\n\n" + pdf_text
                st.success(f"✅ PDF から {len(pdf_text)} 文字を抽出しました")

    # ── ステップ2: URL コンテンツ取得 ─────────────────────────────
    if url_input:
        with st.spinner("🌐 サイトを取得中..."):
            web_result = fetch_url_content(url_input)
            if web_result["error"]:
                st.warning(f"サイト取得: {web_result['error']}")
            else:
                combined_text = combined_text + "\n\n" + web_result["text"]
                st.success(f"✅ サイト取得完了（タイトル: {web_result['title'][:60]}）")

            # ドメイン抽出
            import re
            m = re.search(r"(?:https?://)?([a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,})", url_input)
            if m:
                domain_for_analysis = m.group(1)

    # ── ステップ3: テキスト分析 ──────────────────────────────────
    text_signals = []
    text_score = 0
    financial_claims = []
    company_info = {}

    if combined_text.strip():
        with st.spinner("🔎 テキストを分析中..."):
            text_signals, text_score = analyze_text(combined_text)
            financial_claims = extract_financial_claims(combined_text)
            company_info = extract_company_info(combined_text)

    # ── ステップ4: ドメイン調査 ──────────────────────────────────
    domain_result = {"risks": [], "score": 0}
    if domain_for_analysis:
        with st.spinner("🌐 ドメイン調査中..."):
            domain_result = analyze_domain(domain_for_analysis)
            wb = check_wayback_machine(domain_for_analysis)
            if wb.get("available") and wb.get("first_snapshot"):
                domain_result["wayback_first"] = wb["first_snapshot"]

    # ── ステップ5: 評判検索 ──────────────────────────────────────
    reputation_score = 0
    if project_name:
        with st.spinner(f"🔍 「{project_name}」の評判を検索中..."):
            reputation_results = search_scam_reputation(project_name)
            if reputation_results.get("error"):
                st.warning(f"評判検索: {reputation_results['error']}")
            else:
                mentions = reputation_results.get("scam_mentions", 0)
                if mentions >= 5:
                    reputation_score = 25
                elif mentions >= 3:
                    reputation_score = 15
                elif mentions >= 1:
                    reputation_score = 8

    # ── ステップ6: コントラクト調査 ──────────────────────────────
    contract_result = {"risks": [], "score": 0, "holder_info": {}, "error": None}
    if contract_address.strip():
        with st.spinner("⛓️ コントラクトを調査中..."):
            chain = chain_hint if chain_hint != "auto" else ""
            contract_result = analyze_contract(contract_address.strip(), chain)
            if contract_result.get("error"):
                st.warning(f"コントラクト: {contract_result['error']}")

    # ── スコア集計 ────────────────────────────────────────────────
    total_score = calculate_final_score(
        text_score,
        contract_result.get("score", 0),
        domain_result.get("score", 0),
        reputation_score,
    )

    verdict, verdict_color, ponzi_likelihood = build_verdict(total_score)

    # シグナル分類
    high_signals = [s.category for s in text_signals if s.severity == "high"]
    medium_signals = [s.category for s in text_signals if s.severity == "medium"]
    dangerous_contract = [r.flag for r in contract_result.get("risks", []) if r.is_dangerous]
    high_signals.extend(dangerous_contract[:5])

    all_signal_names = high_signals + medium_signals
    questions = generate_questions(all_signal_names, bool(contract_address.strip()))
    conclusion = generate_conclusion(total_score, high_signals, ponzi_likelihood)

    # ── 出力レポート ──────────────────────────────────────────────
    st.divider()
    st.header("📊 調査レポート")
    st.caption(f"生成日時: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} ／ 対象: {project_name or url_input or contract_address}")

    # 総合判定バナー
    if verdict_color == "red":
        st.error(f"## 総合判定: {verdict}")
    elif verdict_color == "orange":
        st.warning(f"## 総合判定: {verdict}")
    else:
        st.success(f"## 総合判定: {verdict}")

    # スコアゲージ
    col_score, col_ponzi = st.columns(2)
    with col_score:
        st.metric("リスクスコア", f"{total_score} / 100", help="0=安全, 100=最高危険")
        st.progress(total_score / 100)
    with col_ponzi:
        st.metric("詐欺/ポンジ疑いの強さ", ponzi_likelihood)

    st.divider()

    # ── 主な危険シグナル ─────────────────────────────────────────
    st.subheader("🚨 主な危険シグナル")
    if high_signals:
        for s in high_signals:
            st.error(f"⛔ {s}")
    elif medium_signals:
        for s in medium_signals:
            st.warning(f"⚠️ {s}")
    else:
        st.success("重大な危険シグナルは検出されませんでした")

    # ── テキスト分析詳細 ─────────────────────────────────────────
    if text_signals:
        with st.expander("📝 テキスト分析詳細", expanded=True):
            for sig in text_signals:
                icon = "⛔" if sig.severity == "high" else "⚠️" if sig.severity == "medium" else "ℹ️"
                st.markdown(f"{icon} **{sig.category}** （+{sig.score}点）")
                st.caption(f'検出: 「{sig.matched}」')
            if financial_claims:
                st.markdown("**💰 検出された収益・利回り主張:**")
                for c in financial_claims[:10]:
                    st.code(c)

    # ── 収益原資分析 ──────────────────────────────────────────────
    st.subheader("💰 収益原資の分析")
    revenue_signals = [s for s in text_signals if s.category in ["収益原資不明", "固定利回り/日利/月利", "元本保証"]]
    if revenue_signals:
        st.warning("収益の原資・仕組みについて疑念があります")
        for s in revenue_signals:
            st.markdown(f"- **{s.category}**: 「{s.matched}」")
    elif combined_text:
        st.info("テキスト内に明示的な収益保証表現は検出されませんでした（人手による確認推奨）")
    else:
        st.info("テキスト未入力のため分析不可")

    # ── 出金リスク ────────────────────────────────────────────────
    st.subheader("💸 出金リスク")
    withdrawal_signals = [s for s in text_signals if "出金" in s.category or "税金" in s.category or "手数料" in s.category]
    honeypot = any(r.flag == "ハニーポット" and r.is_dangerous for r in contract_result.get("risks", []))
    high_tax = [r for r in contract_result.get("risks", []) if "Tax" in r.flag and r.is_dangerous]

    if withdrawal_signals or honeypot or high_tax:
        for s in withdrawal_signals:
            st.error(f"⛔ {s.category}: 「{s.matched}」")
        if honeypot:
            st.error("⛔ ハニーポット検出: このトークンは**購入後に売却不能**の可能性があります")
        for t in high_tax:
            st.error(f"⛔ {t.flag}: {t.description}")
    else:
        st.success("出金制限に関する直接シグナルは検出されませんでした")

    # ── コントラクト/オンチェーンリスク ──────────────────────────
    st.subheader("⛓️ トークン/オンチェーンリスク")
    if contract_address.strip() and not contract_result.get("error"):
        holder_info = contract_result.get("holder_info", {})
        if holder_info:
            st.markdown(f"**トークン**: {holder_info.get('token_name', '不明')} ({holder_info.get('token_symbol', '?')})")
            st.markdown(f"**保有者数**: {holder_info.get('holder_count', '不明')}")

        contract_risks = contract_result.get("risks", [])
        dangerous = [r for r in contract_risks if r.is_dangerous]
        safe = [r for r in contract_risks if not r.is_dangerous]

        if dangerous:
            st.error(f"危険なコントラクト機能が {len(dangerous)} 件検出されました")
            for r in dangerous:
                st.markdown(f"⛔ **{r.flag}**: {r.description}")
        else:
            st.success("重大なコントラクトリスクは検出されませんでした")

        if safe:
            with st.expander("✅ 正常確認済み項目"):
                for r in safe:
                    st.markdown(f"✅ {r.flag}")

        # 上位保有者集中度
        if holder_info.get("top_holders"):
            conc = holder_info.get("top10_concentration", "不明")
            is_risky = holder_info.get("concentration_risk", False)
            if is_risky:
                st.warning(f"⚠️ 上位10アドレスで **{conc}** を保有（集中リスク高）")
            else:
                st.info(f"上位10アドレスの保有比率: {conc}")

            with st.expander("上位保有者リスト"):
                for h in holder_info.get("top_holders", []):
                    tag = f"[{h['tag']}]" if h.get("tag") else ""
                    st.markdown(f"- `{h['address']}` {h['percent']} {tag}")

    elif contract_address.strip() and contract_result.get("error"):
        st.warning(f"コントラクト調査: {contract_result['error']}")
    else:
        st.info("コントラクトアドレスが入力されていません")

    # ── チーム/会社実体リスク ──────────────────────────────────
    st.subheader("🏢 チーム/会社実体リスク")
    if company_info:
        for k, v in company_info.items():
            label = {"company": "会社名", "representative": "代表者", "address": "所在地", "emails": "メール"}.get(k, k)
            st.markdown(f"- **{label}**: {v}")
        st.caption("※ 抽出情報の正確性は保証されません。必ず一次情報で確認してください。")
    else:
        if combined_text:
            st.warning("⚠️ テキスト内に会社・運営者情報を確認できませんでした（匿名運営の可能性）")
        else:
            st.info("テキスト未入力のため分析不可")

    # ── ドメイン/サイト調査 ────────────────────────────────────
    st.subheader("🌐 ドメイン/サイト調査")
    if domain_for_analysis:
        if domain_result.get("creation_date"):
            age = domain_result.get("age_days", 0)
            st.markdown(f"- **ドメイン**: {domain_result['domain']}")
            st.markdown(f"- **作成日**: {domain_result['creation_date']} （{age}日前）")
            st.markdown(f"- **登録者**: {domain_result.get('registrar', '不明')}")
        if domain_result.get("wayback_first"):
            st.markdown(f"- **最古のWaybackスナップ**: {domain_result['wayback_first'][:4]}年{domain_result['wayback_first'][4:6]}月")
        for risk in domain_result.get("risks", []):
            st.warning(f"⚠️ {risk}")
        if not domain_result.get("risks") and domain_result.get("creation_date"):
            st.success("ドメインに関する重大リスクは検出されませんでした")
        if domain_result.get("error"):
            st.info(f"WHOIS: {domain_result['error']}")
    else:
        st.info("URLが入力されていないためドメイン調査をスキップしました")

    # ── 法規制リスク ──────────────────────────────────────────────
    st.subheader("⚖️ 法規制リスク")
    st.info(
        "**参考情報**\n"
        "- 金融庁登録の有無は「法規制リスク」として参考扱いです（DeFi・海外プロジェクトは未登録が多いため、それだけで詐欺とは判定しません）\n"
        "- 元本保証・利回り保証は日本の金融商品取引法で原則禁止されています\n"
        "- 投資型スキームでの無登録営業は違法です\n"
        "- 各国当局の警告リスト確認: [金融庁](https://www.fsa.go.jp/ordinary/kanyu/20050912.html) / [FTC](https://www.ftc.gov/scams) / [SEC](https://www.sec.gov/tcr)"
    )

    # ── 評判検索結果 ──────────────────────────────────────────────
    if reputation_results and not reputation_results.get("error"):
        st.subheader("🔍 評判・口コミ検索結果")
        mentions = reputation_results.get("scam_mentions", 0)
        if mentions > 0:
            st.error(f"⛔ 詐欺・問題に関連するウェブ情報が **{mentions}件** 検出されました")
        else:
            st.success("詐欺・問題に直接関連する情報は検出されませんでした")

        with st.expander("検索結果一覧"):
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

    # ── 追加確認すべき質問 ────────────────────────────────────────
    st.subheader("❓ 相手に確認すべき質問")
    for i, q in enumerate(questions, 1):
        st.markdown(f"**Q{i}.** {q}")

    # ── 最終結論 ──────────────────────────────────────────────────
    st.divider()
    st.subheader("📌 最終結論")
    if total_score >= 50:
        st.error(conclusion)
    elif total_score >= 30:
        st.warning(conclusion)
    else:
        st.info(conclusion)

    st.divider()
    st.caption(
        "⚠️ **免責事項**: このレポートは自動分析による参考情報です。"
        "投資助言ではありません。最終判断は必ずご自身で行い、必要に応じて専門家にご相談ください。"
        "スコアが低くても投資リスクがゼロであることを意味しません。"
    )
