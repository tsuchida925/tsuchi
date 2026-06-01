"""
リスクスコア算出・総合判定モジュール
"""

from dataclasses import dataclass, field
from typing import List


@dataclass
class RiskReport:
    # スコア（0〜100にクランプ）
    total_score: int = 0
    text_score: int = 0
    contract_score: int = 0
    domain_score: int = 0
    reputation_score: int = 0

    # 判定
    verdict: str = ""          # "危険" / "高リスク" / "要注意" / "低リスク"
    verdict_color: str = ""    # "red" / "orange" / "yellow" / "green"
    ponzi_likelihood: str = "" # "非常に高い" / "高い" / "中程度" / "低い"

    # 詳細シグナル
    high_signals: List[str] = field(default_factory=list)
    medium_signals: List[str] = field(default_factory=list)
    low_signals: List[str] = field(default_factory=list)

    # カテゴリ別リスク
    revenue_risk: str = ""
    withdrawal_risk: str = ""
    contract_risk: str = ""
    team_risk: str = ""
    regulatory_risk: str = ""

    # 追加確認事項
    questions: List[str] = field(default_factory=list)

    # 最終結論
    conclusion: str = ""


def calculate_final_score(
    text_score: int,
    contract_score: int,
    domain_score: int,
    reputation_score: int,
) -> int:
    raw = text_score + contract_score + domain_score + reputation_score
    return min(raw, 100)


def build_verdict(score: int) -> tuple:
    if score >= 70:
        return "危険 ⛔", "red", "非常に高い"
    elif score >= 50:
        return "高リスク 🔴", "orange", "高い"
    elif score >= 30:
        return "要注意 🟡", "orange", "中程度"
    else:
        return "低リスク 🟢", "green", "低い"


def generate_questions(signals: List[str], has_contract: bool) -> List[str]:
    questions = [
        "収益はどこから生まれますか？具体的な収益モデルを説明してください。",
        "運営会社名・代表者・所在地・連絡先を教えてください。",
        "いつでも自由に全額出金できますか？手数料・期間制限・条件はありますか？",
        "過去の出金実績を示す証拠（ブロックチェーントランザクション等）はありますか？",
        "第三者による監査報告書はありますか？",
    ]

    signal_lower = " ".join(signals).lower()

    if "元本保証" in signal_lower or "利回り保証" in signal_lower:
        questions.append("元本・利回りを保証する場合、その原資（資金源）を具体的に説明してください。")

    if "紹介報酬" in signal_lower or "mlm" in signal_lower.lower():
        questions.append("紹介者がいなくなった場合でも収益は継続しますか？新規参加者の資金に依存していませんか？")

    if has_contract:
        questions.append("コントラクトの全権限（Mint・Blacklist・Tax変更等）を放棄した証拠はありますか？")
        questions.append("流動性（LP）はロックされていますか？ロック期間と証拠を提示してください。")

    if "出金" in signal_lower:
        questions.append("出金できない・遅延している利用者がいる場合、その原因と解決策を説明してください。")

    return questions


def generate_conclusion(score: int, high_signals: List[str], ponzi: str) -> str:
    if score >= 70:
        return (
            f"このプロジェクトは複数の深刻な詐欺・ポンジスキームのシグナルを示しており、"
            f"資金投入は**強く非推奨**です。ポンジ構造の可能性は{ponzi}と判定されます。"
            f"特に「{'、'.join(high_signals[:3])}」は典型的な詐欺の特徴です。"
            f"関与前に専門家への相談または当局への届出を検討してください。"
        )
    elif score >= 50:
        return (
            f"このプロジェクトには重大なリスクシグナルが複数検出されています。"
            f"ポンジ構造の可能性は{ponzi}です。追加確認なしに資金を投入することは"
            f"**非推奨**です。運営の透明性・出金の自由・収益原資を必ず確認してください。"
        )
    elif score >= 30:
        return (
            f"いくつかのリスク要因が確認されています。ポンジ可能性は{ponzi}です。"
            f"追加確認事項への明確な回答を得た上で、少額からの検証を推奨します。"
            f"元本は失っても許容できる金額に限定してください。"
        )
    else:
        return (
            f"現時点では重大なリスクシグナルは少ないですが、リスクスコア{score}は"
            f"完全に安全であることを意味しません。暗号資産投資には常にリスクが伴います。"
            f"継続的なモニタリングと分散投資を推奨します。"
        )
