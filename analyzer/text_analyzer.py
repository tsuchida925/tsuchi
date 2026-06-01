"""
テキストベースの詐欺シグナル検出モジュール
"""

import re
from dataclasses import dataclass, field
from typing import List, Tuple

@dataclass
class TextSignal:
    category: str
    severity: str  # "high", "medium", "low"
    message: str
    matched: str
    score: int

# ── 危険パターン定義 ──────────────────────────────────────────────

PATTERNS = [
    # 元本保証
    {
        "category": "元本保証",
        "severity": "high",
        "score": 25,
        "patterns": [
            r"元本保証", r"元本[はが]保証", r"元本を保証", r"guaranteed\s*(principal|capital|investment)",
            r"capital\s*protection", r"no\s*loss", r"損しません", r"損はしない", r"損失なし",
        ]
    },
    # 固定利回り・日利・月利
    {
        "category": "固定利回り/日利/月利",
        "severity": "high",
        "score": 20,
        "patterns": [
            r"日利\s*[\d\.]+\s*%", r"月利\s*[\d\.]+\s*%", r"年利\s*[\d]{3,}",
            r"daily\s*(return|profit|yield|interest)\s*of?\s*[\d\.]+\s*%",
            r"monthly\s*(return|profit|yield|interest)\s*of?\s*[\d\.]+\s*%",
            r"guaranteed\s*([\d\.]+\s*%|return|profit)",
            r"fixed\s*([\d\.]+\s*%|return|yield|interest)",
            r"[\d\.]+%\s*(毎日|毎月|毎週|per\s*day|per\s*month|daily|monthly)",
            r"利益\s*保証", r"収益\s*保証", r"利回り\s*保証",
        ]
    },
    # ノーリスク表現
    {
        "category": "ノーリスク表現",
        "severity": "high",
        "score": 20,
        "patterns": [
            r"リスクなし", r"ノーリスク", r"no[\s\-]?risk", r"risk[\s\-]?free",
            r"zero[\s\-]?risk", r"リスクゼロ", r"リスクはありません",
            r"絶対[に]?儲か", r"必ず儲か", r"確実に[稼|儲]", r"絶対安全",
        ]
    },
    # 出金前の税金・手数料要求（詐欺の典型）
    {
        "category": "出金前の税金・手数料要求",
        "severity": "high",
        "score": 30,
        "patterns": [
            r"出金前[にの].*税", r"出金前[にの].*手数料", r"出金前[にの].*入金",
            r"税金を(払|支払).*出金", r"保証金.*出金", r"手数料.*先払",
            r"withdrawal\s*tax", r"withdrawal\s*fee.*upfront", r"pay.*before.*withdraw",
            r"deposit.*before.*release", r"unlock.*fee", r"release\s*fee",
            r"税金を納めないと", r"手数料を先に", r"先払い.*出金",
        ]
    },
    # 紹介報酬・MLM構造
    {
        "category": "紹介報酬/MLM構造",
        "severity": "medium",
        "score": 15,
        "patterns": [
            r"紹介報酬", r"紹介料", r"リファラル報酬", r"紹介で稼", r"友達紹介",
            r"referral\s*(bonus|reward|commission|program)",
            r"multi[\s\-]?level", r"MLM", r"ネットワークビジネス",
            r"アップライン", r"ダウンライン", r"(2|3|4|5|6|7|8|9|10)[段|階|世代]",
            r"下の人.*稼", r"紹介した人.*収益", r"スポンサー報酬",
        ]
    },
    # 利回り原資不明・曖昧な収益説明
    {
        "category": "収益原資不明",
        "severity": "medium",
        "score": 15,
        "patterns": [
            r"AI.*自動.*利益", r"ボット.*自動.*利益", r"裁定取引.*保証",
            r"高頻度取引.*保証", r"独自.*アルゴリズム.*保証",
            r"blockchain\s*(generates|produces)\s*guaranteed",
            r"staking.*guaranteed.*return", r"passive\s*income.*guaranteed",
            r"収益の仕組みは.*秘密", r"独自技術.*詳細は開示",
        ]
    },
    # 緊急性・希少性の煽り
    {
        "category": "緊急性・希少性の煽り",
        "severity": "medium",
        "score": 10,
        "patterns": [
            r"今すぐ.*登録", r"期間限定", r"先着.*名", r"残り.*枠",
            r"limited\s*time", r"act\s*now", r"don\'t\s*miss", r"exclusive\s*offer",
            r"今だけ", r"チャンスは今", r"乗り遅れる", r"FOMO",
        ]
    },
    # 著名人・企業の無断使用疑い
    {
        "category": "著名人・有名企業の権威利用",
        "severity": "medium",
        "score": 10,
        "patterns": [
            r"イーロン.*マスク.*推薦", r"elon\s*musk.*endorse",
            r"マイクロソフト.*提携", r"microsoft.*partner.*crypto",
            r"ゴールドマン.*サックス.*推薦", r"google.*backed",
            r"政府.*公認", r"government.*approved.*crypto",
            r"SEC.*approved", r"金融庁.*認定.*高利回り",
        ]
    },
    # 出金ロック・制限
    {
        "category": "出金ロック・制限",
        "severity": "medium",
        "score": 15,
        "patterns": [
            r"出金.*\d+[ヶか]月.*禁止", r"出金.*ロック", r"引き出し.*制限",
            r"lock[\s\-]?up\s*period", r"vesting.*\d+\s*(months?|years?)",
            r"withdrawal\s*restriction", r"cannot\s*withdraw",
            r"出金停止", r"出金できません", r"引き出し不可",
        ]
    },
    # 個人情報・秘密鍵要求
    {
        "category": "秘密鍵・個人情報要求",
        "severity": "high",
        "score": 25,
        "patterns": [
            r"秘密鍵.*教えて", r"シードフレーズ.*入力", r"seed\s*phrase.*enter",
            r"private\s*key.*provide", r"wallet.*password.*share",
            r"リカバリーフレーズ.*送", r"ニーモニック.*入力",
        ]
    },
]

# ── 分析関数 ──────────────────────────────────────────────────────

def analyze_text(text: str) -> Tuple[List[TextSignal], int]:
    """テキストを分析して詐欺シグナルと加算スコアを返す"""
    signals: List[TextSignal] = []
    total_score = 0
    seen_categories = {}

    text_lower = text.lower()

    for rule in PATTERNS:
        for pattern in rule["patterns"]:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                cat = rule["category"]
                # 同じカテゴリは最初のマッチのみ記録（重複加点防止）
                if cat not in seen_categories:
                    seen_categories[cat] = True
                    score = rule["score"]
                    total_score += score
                    signals.append(TextSignal(
                        category=cat,
                        severity=rule["severity"],
                        message=_severity_message(rule["severity"]),
                        matched=match.group(0)[:80],
                        score=score,
                    ))
                break

    return signals, total_score


def extract_financial_claims(text: str) -> List[str]:
    """数値入り利回り・収益主張を抽出"""
    claims = []
    patterns = [
        r"[\d\.]+\s*%\s*(利回り|リターン|return|yield|profit|月利|日利|年利)",
        r"(月利|日利|年利|monthly|daily|annual)\s*[\d\.]+\s*%",
        r"[\d\.]+\s*倍[にの]?(なる|増える|増加)",
        r"\$[\d,]+\s*(per\s*(day|month|year)|毎[日月年])",
        r"最大\s*[\d\.]+\s*%",
        r"up\s*to\s*[\d\.]+\s*%",
    ]
    for pat in patterns:
        for m in re.finditer(pat, text, re.IGNORECASE):
            claims.append(m.group(0)[:100])
    return list(set(claims))


def extract_company_info(text: str) -> dict:
    """会社・運営者情報の抽出試行"""
    info = {}

    # 会社名
    m = re.search(r"(株式会社|合同会社|有限会社|Inc\.|Ltd\.|LLC|Corp\.)\s*[^\s\n。]{2,30}", text)
    if m:
        info["company"] = m.group(0)[:50]

    # 代表者
    m = re.search(r"(代表[取締役]?|CEO|Founder|創業者)[：:\s]*([A-Za-z぀-鿿]{2,20})", text)
    if m:
        info["representative"] = m.group(2)[:30]

    # 所在地
    m = re.search(r"(所在地|住所|Address)[：:\s]*([^\n。]{5,60})", text)
    if m:
        info["address"] = m.group(2)[:60]

    # 連絡先
    emails = re.findall(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", text)
    if emails:
        info["emails"] = emails[:3]

    return info


def _severity_message(severity: str) -> str:
    return {
        "high": "高リスクシグナル",
        "medium": "中リスクシグナル",
        "low": "低リスクシグナル",
    }.get(severity, "シグナル")
