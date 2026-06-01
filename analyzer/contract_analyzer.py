"""
オンチェーン・コントラクト分析モジュール
GoPlus Security API（無料・キー不要）を使用
"""

import re
import requests
from dataclasses import dataclass
from typing import Optional, Dict, Any, List

GOPLUS_BASE = "https://api.gopluslabs.io/api/v1"

CHAIN_IDS = {
    "ethereum": "1",
    "eth": "1",
    "bsc": "56",
    "bnb": "56",
    "binance": "56",
    "polygon": "137",
    "matic": "137",
    "arbitrum": "42161",
    "optimism": "10",
    "avalanche": "43114",
    "avax": "43114",
    "base": "8453",
    "solana": "solana",
}

@dataclass
class ContractRisk:
    flag: str
    value: str
    is_dangerous: bool
    score: int
    description: str


def detect_chain(address: str) -> str:
    """アドレス形式からチェーンを推測"""
    address = address.strip()
    if re.match(r"^0x[0-9a-fA-F]{40}$", address):
        return "1"  # デフォルトEthereum（BSCも同形式）
    if re.match(r"^[1-9A-HJ-NP-Za-km-z]{32,44}$", address):
        return "solana"
    return "1"


def analyze_contract(address: str, chain_hint: str = "") -> Dict[str, Any]:
    """
    GoPlus APIでトークンセキュリティを分析
    戻り値: {"risks": List[ContractRisk], "score": int, "raw": dict, "error": str}
    """
    address = address.strip()
    if not address:
        return {"risks": [], "score": 0, "raw": {}, "error": "アドレスが空です"}

    chain_id = CHAIN_IDS.get(chain_hint.lower(), detect_chain(address))

    try:
        if chain_id == "solana":
            url = f"{GOPLUS_BASE}/solana/token_security?contract_addresses={address}"
        else:
            url = f"{GOPLUS_BASE}/token_security/{chain_id}?contract_addresses={address}"

        resp = requests.get(url, timeout=15)
        resp.raise_for_status()
        data = resp.json()

        if data.get("code") != 1:
            return {"risks": [], "score": 0, "raw": {}, "error": f"APIエラー: {data.get('message', '不明')}"}

        result_data = data.get("result", {})
        token_data = result_data.get(address.lower()) or result_data.get(address)

        if not token_data:
            # BSCで再試行
            if chain_id == "1":
                return analyze_contract(address, "bsc")
            return {"risks": [], "score": 0, "raw": {}, "error": "このアドレスのデータが見つかりません（未検証/非EVM）"}

        risks, score = _parse_token_risks(token_data)
        holder_info = _parse_holder_info(token_data)

        return {
            "risks": risks,
            "score": score,
            "raw": token_data,
            "holder_info": holder_info,
            "error": None,
        }

    except requests.RequestException as e:
        return {"risks": [], "score": 0, "raw": {}, "error": f"API接続エラー: {e}"}


def _parse_token_risks(data: dict) -> tuple:
    risks: List[ContractRisk] = []
    total_score = 0

    checks = [
        # (フィールド, "危険値", スコア, フラグ名, 説明)
        ("is_honeypot", "1", 40, "ハニーポット", "買えるが売れないトークン。購入後に出金不能になる。"),
        ("is_open_source", "0", 15, "コントラクト未検証", "ソースコードが公開されていないため内部ロジック不明。"),
        ("is_proxy", "1", 10, "プロキシコントラクト", "管理者がコードを差し替え可能。rug pullリスク。"),
        ("is_mintable", "1", 20, "Mint権限あり", "運営者がトークンを無限発行できる。価値希薄化リスク。"),
        ("can_take_back_ownership", "1", 20, "オーナー権限回収可能", "放棄後もオーナー権限を取り戻せる。"),
        ("owner_change_balance", "1", 25, "残高変更権限", "運営者が任意のウォレット残高を書き換え可能。"),
        ("hidden_owner", "1", 25, "隠れオーナー", "実際のオーナーがコード上で隠蔽されている。"),
        ("selfdestruct", "1", 20, "自壊機能", "コントラクトを消去してTVLを持ち逃げ可能。"),
        ("external_call", "1", 10, "外部コール", "外部コントラクトを呼び出し、動作変更の余地あり。"),
        ("is_blacklisted", "1", 15, "ブラックリスト機能", "特定アドレスの取引を禁止できる。出金制限に悪用可能。"),
        ("is_whitelisted", "1", 10, "ホワイトリスト制限", "ホワイトリスト外アドレスは取引不可。"),
        ("is_anti_whale", "1", 5, "大口制限", "大量売却を制限する機能（一部は正当な用途もあり）。"),
        ("anti_whale_modifiable", "1", 10, "大口制限変更可能", "大口制限ルールを運営者が変更可能。"),
        ("trading_cooldown", "1", 5, "取引クールダウン", "連続取引を制限する機能。"),
        ("personal_slippage_modifiable", "1", 15, "個別スリッページ変更可能", "特定アドレスに高Tax設定で事実上の出金制限可能。"),
        ("is_airdrop_scam", "1", 30, "エアドロップ詐欺フラグ", "既知の詐欺エアドロップと判定。"),
    ]

    for field, danger_val, score, flag, desc in checks:
        val = str(data.get(field, ""))
        is_dangerous = val == danger_val
        if is_dangerous:
            total_score += score
        if val:
            risks.append(ContractRisk(
                flag=flag,
                value="危険" if is_dangerous else "正常",
                is_dangerous=is_dangerous,
                score=score if is_dangerous else 0,
                description=desc,
            ))

    # Buy/Sell Tax
    try:
        buy_tax = float(data.get("buy_tax", 0) or 0)
        sell_tax = float(data.get("sell_tax", 0) or 0)
        if sell_tax > 0.1:
            score_add = min(int(sell_tax * 100), 30)
            total_score += score_add
            risks.append(ContractRisk(
                flag=f"高Sell Tax ({sell_tax*100:.1f}%)",
                value="危険",
                is_dangerous=True,
                score=score_add,
                description=f"売却時に{sell_tax*100:.1f}%の手数料。10%超は事実上の売却制限。",
            ))
        if buy_tax > 0.1:
            risks.append(ContractRisk(
                flag=f"高Buy Tax ({buy_tax*100:.1f}%)",
                value="注意",
                is_dangerous=False,
                score=0,
                description=f"購入時に{buy_tax*100:.1f}%の手数料。",
            ))
    except (ValueError, TypeError):
        pass

    # LP Lock チェック
    lp_holders = data.get("lp_holders", [])
    if isinstance(lp_holders, list) and lp_holders:
        locked = any(str(h.get("is_locked", "0")) == "1" for h in lp_holders)
        if not locked:
            total_score += 15
            risks.append(ContractRisk(
                flag="LP未ロック",
                value="危険",
                is_dangerous=True,
                score=15,
                description="流動性がロックされていない。運営者がLPを引き抜き（rug pull）可能。",
            ))

    return risks, total_score


def _parse_holder_info(data: dict) -> dict:
    info = {}

    # トークン基本情報
    info["token_name"] = data.get("token_name", "不明")
    info["token_symbol"] = data.get("token_symbol", "不明")
    info["total_supply"] = data.get("total_supply", "不明")
    info["holder_count"] = data.get("holder_count", "不明")

    # 上位保有者
    holders = data.get("holders", [])
    if isinstance(holders, list) and holders:
        top_holders = []
        top_pct = 0.0
        for h in holders[:10]:
            try:
                pct = float(h.get("percent", 0) or 0)
                top_pct += pct
                top_holders.append({
                    "address": h.get("address", "")[:20] + "...",
                    "percent": f"{pct*100:.2f}%",
                    "is_contract": h.get("is_contract", "0") == "1",
                    "tag": h.get("tag", ""),
                })
            except (ValueError, TypeError):
                pass
        info["top_holders"] = top_holders
        info["top10_concentration"] = f"{top_pct*100:.1f}%"
        info["concentration_risk"] = top_pct > 0.5  # 50%超で集中リスク

    # LP情報
    lp_holders = data.get("lp_holders", [])
    if isinstance(lp_holders, list):
        info["lp_holders"] = [
            {
                "address": h.get("address", "")[:20] + "...",
                "percent": f"{float(h.get('percent', 0) or 0)*100:.2f}%",
                "is_locked": h.get("is_locked", "0") == "1",
                "tag": h.get("tag", ""),
            }
            for h in lp_holders[:5]
        ]

    # DEX情報
    dex_list = data.get("dex", [])
    if isinstance(dex_list, list):
        info["dex"] = [d.get("name", "") for d in dex_list[:3]]

    return info
