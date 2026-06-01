"""
リスクスコア算出・総合判定モジュール（拡張版）
"""

from dataclasses import dataclass, field
from typing import List, Dict


@dataclass
class StructuralRisk:
    name: str
    level: str    # "high" / "medium" / "low" / "unknown"
    detail: str


def calculate_final_score(
    text_score: int,
    contract_score: int,
    domain_score: int,
    reputation_score: int,
) -> int:
    raw = text_score + contract_score + domain_score + reputation_score
    return min(raw, 100)


def build_verdict(score: int) -> tuple:
    if score >= 81:
        return "参加非推奨 ⛔", "darkred", "非常に高い"
    elif score >= 61:
        return "非常に危険 🔴", "red", "高い"
    elif score >= 41:
        return "高リスク 🟠", "orange", "中〜高"
    elif score >= 21:
        return "要注意 🟡", "yellow", "中程度"
    else:
        return "低リスク 🟢", "green", "低い"


def build_structural_risks(signals, contract_risks, domain_score: int, reputation_score: int) -> List[StructuralRisk]:
    """カテゴリ別構造リスクを生成"""
    cats = {s.category for s in signals}
    risks = []

    # 固定利回りリスク
    if "固定利回り/日利/月利/自動複利" in cats or "元本保証" in cats:
        level = "high"
        detail = "固定利回り・自動複利・元本保証が検出されました。収益原資が外部収益でなく新規参加者資金依存の可能性があります。"
    else:
        level = "low"
        detail = "固定利回り・元本保証の表現は検出されませんでした。"
    risks.append(StructuralRisk("固定利回りリスク", level, detail))

    # MLM/紹介報酬リスク
    if "MLM/チーム報酬/ランク制度" in cats:
        level = "high"
        detail = "多層型の紹介報酬・チーム報酬・ランク制度が検出されました。参加者拡大依存の収益構造の疑いがあります。"
    elif any("紹介" in c for c in cats):
        level = "medium"
        detail = "紹介報酬が確認されています。収益がどの程度参加者拡大に依存しているか要確認です。"
    else:
        level = "low"
        detail = "MLM・紹介報酬構造の明確な表現は検出されませんでした。"
    risks.append(StructuralRisk("MLM/紹介報酬リスク", level, detail))

    # ノード販売リスク
    if "ノード販売/権利販売" in cats:
        level = "high"
        detail = "ノード購入・権利販売が確認されました。購入代金の配当・返金条件・収益原資の検証が必要です。"
    else:
        level = "low"
        detail = "ノード販売・権利販売の表現は検出されませんでした。"
    risks.append(StructuralRisk("ノード販売リスク", level, detail))

    # 上場期待リスク
    if "上場価格・将来価格の断定" in cats or "成功銘柄比較・倍率煽り" in cats:
        level = "high"
        detail = "上場価格の断定・成功銘柄との比較・倍率表現が検出されました。価格期待による勧誘色が強い案件です。"
    else:
        level = "low"
        detail = "上場価格断定・倍率煽りの表現は検出されませんでした。"
    risks.append(StructuralRisk("上場期待リスク", level, detail))

    # 運営実体リスク
    team_signals = [s for s in signals if s.category in ["投資家・財団・提携先による信用補強", "著名人・有名企業の権威利用"]]
    if team_signals:
        level = "medium"
        detail = "投資家・財団・著名人による信用補強表現があります。外部での公式確認が必要です。"
    else:
        level = "unknown"
        detail = "運営者・法人・代表者情報が明確でない可能性があります。テキストから会社情報を確認してください。"
    risks.append(StructuralRisk("運営実体リスク", level, detail))

    # 出金リスク
    withdrawal_signals = [s for s in signals if "出金" in s.category or "税金" in s.category]
    honeypot = any(r.flag == "ハニーポット" and r.is_dangerous for r in contract_risks)
    if "出金前の税金・手数料要求" in cats:
        level = "high"
        detail = "出金前に税金・手数料を要求する表現があります。これは詐欺の最終段階の典型手口です。"
    elif honeypot:
        level = "high"
        detail = "コントラクトにハニーポットが検出されました。購入後に売却不能になる可能性があります。"
    elif withdrawal_signals:
        level = "medium"
        detail = "出金に関する制限・条件の表現があります。詳細確認が必要です。"
    else:
        level = "unknown"
        detail = "出金条件・ロック・手数料について明確な記載が確認できませんでした。"
    risks.append(StructuralRisk("出金リスク", level, detail))

    # オンチェーン透明性リスク
    dangerous_contract = [r for r in contract_risks if r.is_dangerous]
    if dangerous_contract:
        level = "high"
        detail = f"危険なコントラクト機能が{len(dangerous_contract)}件検出されました: {', '.join(r.flag for r in dangerous_contract[:3])}"
    elif contract_risks:
        level = "low"
        detail = "コントラクトに重大なリスクは検出されませんでした。"
    else:
        level = "unknown"
        detail = "コントラクトアドレスが未入力または調査不能です。"
    risks.append(StructuralRisk("オンチェーン透明性リスク", level, detail))

    # 実需/収益原資リスク
    if "流行ワード過多/実需不明" in cats or "収益原資不明" in cats:
        level = "medium"
        detail = "流行ワードが多用されていますが、実際の外部収益源・利用者・取引量が不明です。"
    elif any(s.category == "固定利回り/日利/月利/自動複利" for s in signals):
        level = "medium"
        detail = "固定利回りの原資となる外部収益が明確でありません。"
    else:
        level = "unknown"
        detail = "収益原資の明確な記載が確認できませんでした。"
    risks.append(StructuralRisk("実需/収益原資リスク", level, detail))

    # 法規制リスク
    jp_law_risks = [s for s in signals if s.category in [
        "元本保証", "固定利回り/日利/月利/自動複利", "MLM/チーム報酬/ランク制度"
    ]]
    if jp_law_risks:
        level = "medium"
        detail = "元本保証・固定利回り・紹介報酬が組み合わさる場合、日本の金融商品取引法・特定商取引法に抵触する可能性があります（海外案件はグレーゾーンですが参考リスクとして記載）。"
    else:
        level = "low"
        detail = "明確な法規制抵触表現は検出されませんでした。ただし金融庁登録の有無は別途確認してください。"
    risks.append(StructuralRisk("法規制リスク", level, detail))

    return risks


def generate_conclusion(score: int, high_signals: List[str], ponzi: str) -> str:
    if score >= 61:
        return (
            f"このプロジェクトには複数の深刻なリスクシグナルが検出されており、"
            f"追加確認なしでの参加は**非推奨**です。"
            f"ポンジ構造・詐欺の可能性は{ponzi}と判定されます。"
            f"特に「{'、'.join(high_signals[:3])}」は注意が必要です。"
            f"少額でも参加前に全項目を確認し、専門家への相談を検討してください。"
        )
    elif score >= 41:
        return (
            f"重大なリスクシグナルが複数検出されています。ポンジ構造の可能性は{ponzi}です。"
            f"追加確認事項への明確な回答・証拠を得るまでは参加を保留することを推奨します。"
            f"少額テストでも慎重に行い、元本を失っても許容できる金額に限定してください。"
        )
    elif score >= 21:
        return (
            f"いくつかのリスク要因が確認されています。可能性は{ponzi}です。"
            f"追加確認事項への回答を得た上で、少額からの検証を推奨します。"
        )
    else:
        return (
            f"現時点では重大なリスクシグナルは少ないですが、"
            f"リスクスコア{score}は完全に安全であることを意味しません。"
            f"継続的なモニタリングと分散投資を推奨します。"
        )
