"""
ドメイン・サイト調査モジュール（WHOIS、年齢、サイト品質）
"""

import re
import socket
from datetime import datetime, timezone
from typing import Dict, Any

try:
    import whois
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False


def analyze_domain(url_or_domain: str) -> Dict[str, Any]:
    domain = _extract_domain(url_or_domain)
    result = {
        "domain": domain,
        "age_days": None,
        "creation_date": None,
        "registrar": None,
        "country": None,
        "risks": [],
        "score": 0,
        "error": None,
    }

    if not domain:
        result["error"] = "ドメインを抽出できませんでした"
        return result

    # IP解決チェック
    try:
        socket.gethostbyname(domain)
    except socket.gaierror:
        result["risks"].append("ドメインが解決不能（サイト閉鎖・偽ドメインの可能性）")
        result["score"] += 10

    if not WHOIS_AVAILABLE:
        result["error"] = "python-whoisが未インストール（pip install python-whois）"
        return result

    try:
        w = whois.whois(domain)

        # 作成日
        creation = w.creation_date
        if isinstance(creation, list):
            creation = creation[0]
        if creation:
            if creation.tzinfo is None:
                creation = creation.replace(tzinfo=timezone.utc)
            age = (datetime.now(timezone.utc) - creation).days
            result["age_days"] = age
            result["creation_date"] = creation.strftime("%Y-%m-%d")

            if age < 30:
                result["risks"].append(f"ドメイン作成から{age}日以内（極めて新しい）")
                result["score"] += 20
            elif age < 180:
                result["risks"].append(f"ドメイン作成から{age}日（6ヶ月未満）")
                result["score"] += 10
            elif age < 365:
                result["risks"].append(f"ドメイン作成から{age}日（1年未満）")
                result["score"] += 5

        result["registrar"] = str(w.registrar or "不明")[:60]
        result["country"] = str(w.country or "不明")[:20]

        # プライバシー保護（WHOIS非公開）
        registrant = str(w.registrant_name or w.name or "")
        if "privacy" in registrant.lower() or "proxy" in registrant.lower() or "redacted" in registrant.lower():
            result["risks"].append("WHOIS情報がプライバシー保護（運営者特定困難）")
            result["score"] += 5

    except Exception as e:
        result["error"] = f"WHOIS取得エラー: {str(e)[:80]}"

    return result


def _extract_domain(url_or_domain: str) -> str:
    url = url_or_domain.strip()
    # URL形式の場合
    m = re.search(r"(?:https?://)?([a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,})", url)
    if m:
        domain = m.group(1)
        # wwwを除去
        if domain.startswith("www."):
            domain = domain[4:]
        return domain
    return ""
