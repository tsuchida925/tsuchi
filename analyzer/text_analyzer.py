"""
テキストベースの詐欺シグナル検出モジュール（拡張版）
"""

import re
from dataclasses import dataclass, field
from typing import List, Tuple, Dict, Any

@dataclass
class TextSignal:
    category: str
    severity: str  # "high", "medium", "low"
    message: str
    matched: str
    score: int
    reason: str = ""  # なぜ危険か

# ── 危険パターン定義 ──────────────────────────────────────────────

PATTERNS = [
    # ── 元本保証 ──────────────────────────────────────────────────
    {
        "category": "元本保証",
        "severity": "high",
        "score": 25,
        "reason": "元本保証は日本の金融商品取引法で原則禁止されており、収益原資が不明な場合は新規参加者資金で補填されるポンジ構造の典型です。",
        "patterns": [
            r"元本保証", r"元本[はが]保証", r"元本を保証",
            r"guaranteed\s*(principal|capital|investment)",
            r"capital\s*protection", r"no\s*loss",
            r"損しません", r"損はしない", r"損失なし",
            r"無損失投資", r"無損失", r"損失なし", r"100%下支え",
        ]
    },
    # ── 固定利回り・日利・月利・自動複利 ──────────────────────────
    {
        "category": "固定利回り/日利/月利/自動複利",
        "severity": "high",
        "score": 25,
        "reason": "固定の日利・月利・自動複利は、収益原資が外部収益でなく新規参加者資金やトークン発行に依存するポンジ/内部循環構造の典型です。",
        "patterns": [
            r"日利\s*[\d\.]+\s*%", r"月利\s*[\d\.]+\s*%",
            r"最大日利", r"最大月利",
            r"毎日自動複利", r"自動複利", r"毎日複利",
            r"毎日配当", r"毎日報酬", r"日次産出", r"日次報酬",
            r"daily\s*(return|profit|yield|interest)\s*of?\s*[\d\.]+\s*%",
            r"monthly\s*(return|profit|yield|interest)\s*of?\s*[\d\.]+\s*%",
            r"guaranteed\s*([\d\.]+\s*%|return|profit)",
            r"fixed\s*([\d\.]+\s*%|return|yield|interest)",
            r"[\d\.]+%\s*(毎日|毎月|毎週|per\s*day|per\s*month|daily|monthly)",
            r"利益\s*保証", r"収益\s*保証", r"利回り\s*保証",
            r"永続的.*報酬", r"排除なし",
            r"静的マイニング", r"静的ステーキング",
            r"PoS産出", r"ハッシュパワー補償",
        ]
    },
    # ── ノーリスク表現 ────────────────────────────────────────────
    {
        "category": "ノーリスク表現",
        "severity": "high",
        "score": 20,
        "reason": "投資にノーリスクは存在しません。この表現は初心者を安心させて勧誘するための典型的な詐欺文句です。",
        "patterns": [
            r"リスクなし", r"ノーリスク", r"no[\s\-]?risk", r"risk[\s\-]?free",
            r"zero[\s\-]?risk", r"リスクゼロ", r"リスクはありません",
            r"絶対[に]?儲か", r"必ず儲か", r"確実に[稼|儲]", r"絶対安全",
        ]
    },
    # ── 出金前の税金・手数料要求 ──────────────────────────────────
    {
        "category": "出金前の税金・手数料要求",
        "severity": "high",
        "score": 35,
        "reason": "出金前に税金・保証金・手数料を要求するのは詐欺の最終段階の典型手口です。正規のサービスは出金前に別途入金を求めません。",
        "patterns": [
            r"出金前[にの].*税", r"出金前[にの].*手数料", r"出金前[にの].*入金",
            r"税金を(払|支払).*出金", r"保証金.*出金", r"手数料.*先払",
            r"withdrawal\s*tax", r"withdrawal\s*fee.*upfront",
            r"pay.*before.*withdraw", r"deposit.*before.*release",
            r"unlock.*fee", r"release\s*fee",
            r"税金を納めないと", r"手数料を先に", r"先払い.*出金",
        ]
    },
    # ── MLM/チーム報酬/ランク制度 ─────────────────────────────────
    {
        "category": "MLM/チーム報酬/ランク制度",
        "severity": "high",
        "score": 25,
        "reason": "紹介報酬だけでなくチーム実績・ランク・報酬プールに基づく多層型インセンティブは、商品・実需よりも参加者拡大が収益源になるポンジ/MLM構造の特徴です。",
        "patterns": [
            r"紹介報酬", r"紹介料", r"リファラル報酬", r"紹介で稼", r"友達紹介",
            r"referral\s*(bonus|reward|commission|program)",
            r"動的チーム報酬", r"チーム報酬", r"動的管理報酬", r"動的報酬",
            r"multi[\s\-]?level", r"MLM", r"ネットワークビジネス",
            r"V[1-9]|V10", r"ランク[制度報酬]", r"小区分実績", r"大区分実績",
            r"報酬プール", r"コミュニティ報酬", r"DAO報酬",
            r"直紹介", r"間接紹介", r"グループ実績", r"バイナリー", r"ユニレベル",
            r"アップライン", r"ダウンライン",
            r"(2|3|4|5|6|7|8|9|10)[段|階|世代]",
        ]
    },
    # ── ノード販売・権利販売 ──────────────────────────────────────
    {
        "category": "ノード販売/権利販売",
        "severity": "high",
        "score": 25,
        "reason": "ノード購入により配当・紹介報酬・トークン特典が付与される設計は、実際のノード運用実体・収益原資・返金条件の検証が必要です。価格が高額なほど回収期待と依存が生まれます。",
        "patterns": [
            r"ノード権益", r"スーパーノード", r"量子ノード", r"創世ノード",
            r"ジェネシスノード", r"ノード価格", r"ノード購入", r"ノード販売",
            r"実機マイナー", r"マイニング機器", r"算力贈呈",
            r"ハッシュパワー", r"出金手数料配当",
            r"DAO権益", r"特典トークン", r"特典BOT", r"ノード報酬",
            r"全網演算力", r"全網配当",
            r"(super|quantum|genesis|master)\s*node",
        ]
    },
    # ── 上場価格・将来価格の断定 ──────────────────────────────────
    {
        "category": "上場価格・将来価格の断定",
        "severity": "high",
        "score": 20,
        "reason": "将来の上場価格・上場先を断定・示唆する表現は、価格期待による勧誘色が強く、実現可能性の確認が必要です。未上場トークンの価格予告は多くの国で規制対象です。",
        "patterns": [
            r"上場価格", r"上場予定", r"上場後価格", r"確定上場", r"取引所上場決定",
            r"主要取引所.*[0-9]+.*社", r"[0-9]+.*社.*上場",
            r"初値", r"プレセール価格", r"私募価格",
            r"Binance.*上場", r"OKX.*上場", r"Bybit.*上場",
            r"MEXC.*上場", r"Gate.*上場", r"Bitget.*上場",
            r"\$\s*[0-9]+.*上場", r"上場.*\$\s*[0-9]+",
            r"listing\s*price", r"expected.*listing",
        ]
    },
    # ── 成功銘柄比較・倍率煽り ────────────────────────────────────
    {
        "category": "成功銘柄比較・倍率煽り",
        "severity": "high",
        "score": 20,
        "reason": "既存の成功チェーンや過去の大幅上昇銘柄との比較は、技術・実需・流動性の根拠なく価格期待を利用した勧誘表現です。過去の上昇は将来を保証しません。",
        "patterns": [
            r"次の(ETH|SOL|BNB|BTC|イーサリアム|ソラナ)",
            r"パブリックチェーン\s*4\.0", r"第[四4]世代",
            r"[0-9,]+万倍", r"[0-9,]+千倍", r"[0-9,]+百倍",
            r"4200万倍", r"16520倍", r"9166倍", r"1340倍",
            r"100倍", r"1000倍", r"万倍",
            r"神話.*暗号", r"暗号.*神話", r"富を育む", r"暗号資産の富",
            r"価値の源泉", r"ジェネシスマイニング",
            r"(ETH|BNB|SOL|BTC).*上昇率.*比較",
            r"比較.*上昇率.*(ETH|BNB|SOL|BTC)",
        ]
    },
    # ── 投資家・財団・提携先の信用補強 ──────────────────────────
    {
        "category": "投資家・財団・提携先による信用補強",
        "severity": "medium",
        "score": 15,
        "reason": "投資家・財団名が記載されていても、投資家側の公式発表・登記・ニュースリリースで確認できない場合、信用補強目的の名称利用の可能性があります。",
        "patterns": [
            r"(Foundation|Capital|Ventures|Fund|Labs)\s+[が投資支援出資バック]",
            r"[投資家出資]\s*(Foundation|Capital|Ventures)",
            r"リード投資家", r"戦略投資", r"資金調達.*[0-9]+",
            r"[0-9]+万ドル.*調達", r"[0-9]+百万.*調達",
            r"NIX|Alpha\s*Capital|Gemhead",
            r"Binance\s*Alpha", r"国家級", r"グローバルファンド",
            r"主要メディア.*掲載", r"掲載.*主要メディア",
            r"監査.*完了", r"セキュリティ監査.*済",
            r"backed\s*by", r"funded\s*by", r"supported\s*by",
        ]
    },
    # ── ロードマップ過密 ──────────────────────────────────────────
    {
        "category": "ロードマップ過密",
        "severity": "medium",
        "score": 15,
        "reason": "短期間でメインネット・監査・DEX・ブリッジ・ウォレット・複数取引所上場が予定されている場合、技術開発・監査・上場審査の現実性に対してロードマップが過密な可能性があります。",
        "patterns": [
            r"メインネット.*テストネット.*DEX.*ウォレット",
            r"メインネット.*監査.*上場",
            r"(Q[1-4]|第[一二三四1234]四半期).*メインネット.*DEX",
            r"roadmap.*mainnet.*dex.*bridge",
        ]
    },
    # ── 流行ワード過多 ────────────────────────────────────────────
    {
        "category": "流行ワード過多/実需不明",
        "severity": "medium",
        "score": 10,
        "reason": "AI・DePIN・GPU・PoSなどの流行ワードが多用されていても、外部顧客からの実収益・利用者数・取引量・Gas発生源が不明な場合、内部循環の可能性があります。",
        "patterns": [
            r"(AI|DePIN|GPU|PoS|PoW).*DEX.*クロスチェーン",
            r"vCompute|分散型計算|スーパーコンピューティング",
            r"無限焼却|デフレトークン|Gas還元",
        ]
    },
    # ── 緊急性・希少性の煽り ──────────────────────────────────────
    {
        "category": "緊急性・希少性の煽り",
        "severity": "medium",
        "score": 10,
        "reason": "限定・期間限定・残り枠などの表現は、冷静な判断を妨げ即決を促す勧誘手法です。",
        "patterns": [
            r"今すぐ.*登録", r"期間限定", r"先着.*名", r"残り.*枠",
            r"limited\s*time", r"act\s*now", r"don\'t\s*miss",
            r"今だけ", r"チャンスは今", r"乗り遅れる", r"FOMO",
        ]
    },
    # ── 出金ロック・制限 ──────────────────────────────────────────
    {
        "category": "出金ロック・制限",
        "severity": "medium",
        "score": 15,
        "reason": "出金に条件・制限・ロック期間がある場合、資金を取り戻せないリスクがあります。",
        "patterns": [
            r"出金.*\d+[ヶか]月.*禁止", r"出金.*ロック", r"引き出し.*制限",
            r"lock[\s\-]?up\s*period", r"vesting.*\d+\s*(months?|years?)",
            r"withdrawal\s*restriction", r"cannot\s*withdraw",
            r"出金停止", r"出金できません", r"引き出し不可",
        ]
    },
    # ── 著名人・企業の権威利用 ────────────────────────────────────
    {
        "category": "著名人・有名企業の権威利用",
        "severity": "medium",
        "score": 10,
        "reason": "著名人や大手企業の名前を無断使用・誇張することで信用を偽装する詐欺手法です。",
        "patterns": [
            r"イーロン.*マスク.*推薦", r"elon\s*musk.*endorse",
            r"マイクロソフト.*提携", r"google.*backed",
            r"政府.*公認", r"government.*approved.*crypto",
            r"SEC.*approved", r"金融庁.*認定.*高利回り",
        ]
    },
    # ── 秘密鍵・個人情報要求 ──────────────────────────────────────
    {
        "category": "秘密鍵・シードフレーズ要求",
        "severity": "high",
        "score": 35,
        "reason": "秘密鍵・シードフレーズを他者に渡すとウォレット内の全資産を即時盗まれます。正規サービスは絶対に要求しません。",
        "patterns": [
            r"秘密鍵.*教えて", r"シードフレーズ.*入力", r"seed\s*phrase.*enter",
            r"private\s*key.*provide", r"wallet.*password.*share",
            r"リカバリーフレーズ.*送", r"ニーモニック.*入力",
        ]
    },
]

# ── 流行ワードリスト（個数カウント用）────────────────────────────

BUZZWORDS = [
    "AI", "Web3", "DePIN", "GPU", "CPU", "PoS", "PoW", "DEX", "Swap",
    "MEME", "RWA", "クロスチェーン", "ブリッジ", "DAO", "DID", "NFT",
    "Lending", "Governance", "モジュール", "プロトコル", "vCompute",
    "分散型計算", "スーパーコンピューティング", "量子", "エコシステム",
    "ガス還元", "無限焼却", "デフレ", "DeFi", "Layer2", "ZK",
]

# ── 外部確認が必要な主張を抽出するパターン ───────────────────────

CLAIM_PATTERNS = [
    (r"(NIX\s*Foundation|Alpha\s*Capital|Gemhead\s*Capital|[A-Z][a-z]+\s*(Foundation|Capital|Ventures|Fund))", "投資家・財団名"),
    (r"[0-9,]+\s*(万|百万|億)?\s*(ドル|USD|USDT)\s*(資金調達|調達|出資)", "資金調達額"),
    (r"(Binance|OKX|Bybit|MEXC|Gate|Bitget|Coinbase|Kraken)\s*(上場|listing)", "上場予定取引所"),
    (r"(セキュリティ)?監査\s*(完了|済|実施|予定)", "監査実施"),
    (r"メインネット\s*(稼働|ローンチ|リリース|完成)", "メインネット稼働"),
    (r"DEX\s*(稼働|ローンチ|リリース|完成)", "DEX稼働"),
    (r"(クロスチェーン)?ブリッジ\s*(稼働|完成)", "ブリッジ稼働"),
    (r"実機マイナー|マイニング機器", "実機マイナー"),
    (r"出金\s*(実績|TxID|TX|トランザクション)", "出金実績"),
    (r"(株式会社|合同会社|Inc\.|Ltd\.|LLC|Corp\.)\s*[^\s\n。]{2,30}", "運営法人"),
    (r"(代表|CEO|Founder)\s*[：:]\s*[^\s\n。]{2,20}", "代表者"),
    (r"[0-9]+〜[0-9]+社.*上場|主要取引所.*[0-9]+社", "取引所上場数の主張"),
    (r"\$\s*[0-9]+.*上場価格|上場価格.*\$\s*[0-9]+", "上場価格の主張"),
]

# ── 分析関数 ──────────────────────────────────────────────────────

def analyze_text(text: str) -> Tuple[List[TextSignal], int]:
    """テキストを分析して詐欺シグナルと加算スコアを返す"""
    signals: List[TextSignal] = []
    total_score = 0
    seen_categories = {}

    for rule in PATTERNS:
        for pattern in rule["patterns"]:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                cat = rule["category"]
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
                        reason=rule.get("reason", ""),
                    ))
                break

    # 固定利回り + MLMの複合リスク加点
    has_yield = any(s.category == "固定利回り/日利/月利/自動複利" for s in signals)
    has_mlm = any(s.category == "MLM/チーム報酬/ランク制度" for s in signals)
    if has_yield and has_mlm:
        total_score += 10
        signals.append(TextSignal(
            category="複合リスク（固定利回り×MLM）",
            severity="high",
            message="高リスクシグナル",
            matched="固定利回り＋MLM構造の同時検出",
            score=10,
            reason="固定利回りとMLM紹介報酬が同時に存在する場合、収益の多くが新規参加者の資金によって賄われるポンジ構造の可能性が非常に高くなります。",
        ))

    # 流行ワード個数カウント
    buzzword_hits = [bw for bw in BUZZWORDS if re.search(bw, text, re.IGNORECASE)]
    if len(buzzword_hits) >= 6:
        score = min(len(buzzword_hits) * 2, 20)
        total_score += score
        signals.append(TextSignal(
            category="流行ワード過多/実需不明",
            severity="medium",
            message="中リスクシグナル",
            matched=f"{len(buzzword_hits)}個検出: {', '.join(buzzword_hits[:8])}",
            score=score,
            reason="AI・DePIN・GPU・PoS・DEX・クロスチェーンなどの流行ワードが多数使われていますが、外部顧客からの実収益・利用者数・取引量・Gas発生源が明確でない場合、内部循環の可能性があります。",
        ))

    return signals, total_score


def classify_case_types(signals: List[TextSignal]) -> List[str]:
    """検出シグナルから案件タイプを分類"""
    types = []
    cats = {s.category for s in signals}

    if "固定利回り/日利/月利/自動複利" in cats:
        types.append("固定利回り型")
        types.append("自動複利型")
    if "MLM/チーム報酬/ランク制度" in cats:
        types.append("MLM/チーム報酬型")
    if "ノード販売/権利販売" in cats:
        types.append("ノード販売型")
    if "上場価格・将来価格の断定" in cats:
        types.append("上場期待型")
    if "成功銘柄比較・倍率煽り" in cats:
        types.append("成功銘柄比較煽り型")
    if "投資家・財団・提携先による信用補強" in cats:
        types.append("投資家・財団による信用補強型")
    if "ロードマップ過密" in cats:
        types.append("ロードマップ過密型")
    if "流行ワード過多/実需不明" in cats:
        types.append("実需不明の内部循環型")
    if "出金ロック・制限" in cats or "出金前の税金・手数料要求" in cats:
        types.append("出金リスク不明型")
    if not any("会社" in s.matched or "法人" in s.matched for s in signals):
        types.append("運営実体不明型")

    return types if types else ["判定不能（情報不足）"]


def extract_claims(text: str) -> List[Dict[str, str]]:
    """外部確認が必要な主張を抽出"""
    claims = []
    for pattern, label in CLAIM_PATTERNS:
        for m in re.finditer(pattern, text, re.IGNORECASE):
            claims.append({"label": label, "text": m.group(0)[:100]})
    return claims


def analyze_reward_structure(text: str) -> Dict[str, List[str]]:
    """報酬構造を分類して抽出"""
    structure = {
        "固定報酬": [],
        "紹介報酬": [],
        "チーム/ランク報酬": [],
        "ノード配当": [],
        "ステーキング報酬": [],
        "その他": [],
    }

    patterns_map = {
        "固定報酬": [r"日利[^\n。]{0,30}", r"月利[^\n。]{0,30}", r"最大日利[^\n。]{0,30}", r"固定利回り[^\n。]{0,30}", r"自動複利[^\n。]{0,30}"],
        "紹介報酬": [r"紹介報酬[^\n。]{0,40}", r"リファラル[^\n。]{0,40}", r"直紹介[^\n。]{0,40}"],
        "チーム/ランク報酬": [r"チーム報酬[^\n。]{0,40}", r"動的[^\n。]{0,40}", r"V[1-9][^\n。]{0,30}", r"ランク[^\n。]{0,40}"],
        "ノード配当": [r"ノード[^\n。]{0,40}", r"スーパーノード[^\n。]{0,40}", r"全網配当[^\n。]{0,40}"],
        "ステーキング報酬": [r"ステーキング[^\n。]{0,40}", r"PoS産出[^\n。]{0,40}", r"静的[^\n。]{0,40}"],
    }

    for key, pats in patterns_map.items():
        for pat in pats:
            for m in re.finditer(pat, text, re.IGNORECASE):
                txt = m.group(0).strip()[:80]
                if txt and txt not in structure[key]:
                    structure[key].append(txt)

    return {k: v for k, v in structure.items() if v}


def analyze_revenue_source(text: str, signals: List[TextSignal]) -> Dict[str, str]:
    """収益原資マップを分析"""
    cats = {s.category for s in signals}

    has_external = bool(re.search(
        r"(外部|実需|顧客|利用者|取引手数料|Gas|広告収入|法人契約|サービス料)",
        text, re.IGNORECASE
    ))
    has_token_issuance = bool(re.search(r"(トークン発行|新規発行|mint|鋳造)", text, re.IGNORECASE))
    has_new_member = "MLM/チーム報酬/ランク制度" in cats or "ノード販売/権利販売" in cats

    if has_external:
        who_pays = "外部サービス収益（要確認）"
    elif has_new_member:
        who_pays = "⚠️ 新規参加者資金の可能性あり"
    elif has_token_issuance:
        who_pays = "⚠️ トークン発行による内部循環の可能性"
    else:
        who_pays = "不明（説明なし）"

    return {
        "誰が支払うのか": who_pays,
        "外部収益の有無": "確認済み" if has_external else "不明・記載なし",
        "新規参加者資金依存": "あり（疑い）" if has_new_member else "不明",
        "トークン発行による内部循環": "疑いあり" if has_token_issuance else "不明",
        "実需・利用者の記載": "あり" if has_external else "なし・不明",
    }


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
        r"上場価格.*\$[\d\.]+",
        r"\$[\d\.]+.*上場",
    ]
    for pat in patterns:
        for m in re.finditer(pat, text, re.IGNORECASE):
            claims.append(m.group(0)[:100])
    return list(set(claims))


def extract_company_info(text: str) -> dict:
    """会社・運営者情報の抽出試行"""
    info = {}
    m = re.search(r"(株式会社|合同会社|有限会社|Inc\.|Ltd\.|LLC|Corp\.)\s*[^\s\n。]{2,30}", text)
    if m:
        info["company"] = m.group(0)[:50]
    m = re.search(r"(代表[取締役]?|CEO|Founder|創業者)[：:\s]*([A-Za-z぀-鿿]{2,20})", text)
    if m:
        info["representative"] = m.group(2)[:30]
    m = re.search(r"(所在地|住所|Address)[：:\s]*([^\n。]{5,60})", text)
    if m:
        info["address"] = m.group(2)[:60]
    emails = re.findall(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", text)
    if emails:
        info["emails"] = emails[:3]
    return info


def generate_questions(signals: List[TextSignal], has_contract: bool) -> List[str]:
    """案件内容に応じた確認質問を生成"""
    questions = [
        "公式サイト・Explorer・GitHub・ホワイトペーパーのURLを教えてください。",
        "運営会社名・代表者・所在地・登記情報を教えてください。",
        "いつでも自由に全額出金できますか？手数料・期間制限・条件はありますか？",
    ]
    cats = {s.category for s in signals}

    if "固定利回り/日利/月利/自動複利" in cats:
        questions.append("最大日利・月利の収益原資を具体的に説明してください。新規参加者の資金以外の外部収益は何ですか？")
    if "MLM/チーム報酬/ランク制度" in cats:
        questions.append("紹介者がいなくなっても、日利・配当・出金は継続しますか？新規参加者の増加に収益が依存していませんか？")
    if "ノード販売/権利販売" in cats:
        questions.append("ノード購入者に支払われる配当の原資は何ですか？ノード機器の所有権・返金条件を教えてください。")
    if "上場価格・将来価格の断定" in cats:
        questions.append("上場価格や上場予定取引所の根拠（取引所との契約書等）を提示してください。")
    if "投資家・財団・提携先による信用補強" in cats:
        questions.append("投資家・財団・提携先の公式発表URL・プレスリリースを提示してください。")
    if has_contract:
        questions.append("コントラクトアドレスを教えてください。Mint・Blacklist・Tax変更権限は放棄済みですか？")
        questions.append("流動性（LP）はロックされていますか？ロック期間と証拠を提示してください。")

    questions.extend([
        "過去の出金実績のTxID（ブロックチェーントランザクション）を提示できますか？",
        "第三者によるセキュリティ監査報告書のURLを提示してください。",
        "運営者・代表者が公開の場に顔出しで登場している実績はありますか？",
    ])
    return questions


def _severity_message(severity: str) -> str:
    return {
        "high": "高リスクシグナル",
        "medium": "中リスクシグナル",
        "low": "低リスクシグナル",
    }.get(severity, "シグナル")
