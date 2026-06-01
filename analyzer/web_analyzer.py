"""
URL・Webコンテンツ取得・評判検索モジュール
"""

import re
import time
import requests
from typing import Dict, Any, List
from bs4 import BeautifulSoup

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
}

SCAM_SEARCH_KEYWORDS = [
    "scam", "fraud", "rug pull", "rugpull", "ponzi", "pyramid",
    "出金できない", "詐欺", "ポンジ", "持ち逃げ", "withdrawal problem",
    "withdrawal issue", "exit scam", "fake", "警告",
]


def fetch_url_content(url: str) -> Dict[str, Any]:
    """URLのコンテンツを取得してテキストを抽出"""
    result = {"text": "", "title": "", "error": None, "url": url}
    try:
        url = url.strip()
        if not url.startswith("http"):
            url = "https://" + url
        resp = requests.get(url, headers=HEADERS, timeout=15)
        resp.raise_for_status()
        soup = BeautifulSoup(resp.text, "lxml")

        # タイトル
        title_tag = soup.find("title")
        result["title"] = title_tag.get_text(strip=True)[:100] if title_tag else ""

        # 不要タグ除去
        for tag in soup(["script", "style", "nav", "footer", "header"]):
            tag.decompose()

        result["text"] = soup.get_text(separator=" ", strip=True)[:8000]
    except requests.RequestException as e:
        result["error"] = f"サイト取得エラー: {str(e)[:80]}"
    except Exception as e:
        result["error"] = f"解析エラー: {str(e)[:80]}"
    return result


def search_scam_reputation(project_name: str) -> Dict[str, Any]:
    """DuckDuckGoで詐欺・問題評判を検索"""
    result = {"results": [], "scam_mentions": 0, "error": None}

    try:
        from duckduckgo_search import DDGS
        queries = [
            f"{project_name} scam",
            f"{project_name} 詐欺",
            f"{project_name} withdrawal problem",
            f"{project_name} rug pull",
        ]

        scam_count = 0
        all_results = []

        with DDGS() as ddgs:
            for q in queries[:2]:  # レート制限考慮で2クエリのみ
                try:
                    results = list(ddgs.text(q, max_results=5))
                    for r in results:
                        title = r.get("title", "")
                        body = r.get("body", "")
                        combined = (title + " " + body).lower()
                        is_scam_hit = any(kw in combined for kw in SCAM_SEARCH_KEYWORDS)
                        if is_scam_hit:
                            scam_count += 1
                        all_results.append({
                            "title": title[:80],
                            "url": r.get("href", "")[:100],
                            "snippet": body[:150],
                            "is_scam_related": is_scam_hit,
                        })
                    time.sleep(1)  # レート制限
                except Exception:
                    pass

        result["results"] = all_results[:10]
        result["scam_mentions"] = scam_count

    except ImportError:
        result["error"] = "duckduckgo-searchが未インストール（pip install duckduckgo-search）"
    except Exception as e:
        result["error"] = f"検索エラー: {str(e)[:80]}"

    return result


def check_wayback_machine(domain: str) -> Dict[str, Any]:
    """Wayback Machineで最古のアーカイブを確認"""
    result = {"first_snapshot": None, "available": False, "error": None}
    try:
        url = f"https://archive.org/wayback/available?url={domain}"
        resp = requests.get(url, timeout=10)
        data = resp.json()
        snapshot = data.get("archived_snapshots", {}).get("closest", {})
        if snapshot.get("available"):
            result["available"] = True
            result["first_snapshot"] = snapshot.get("timestamp", "")[:8]  # YYYYMMDD
        else:
            result["available"] = False
    except Exception as e:
        result["error"] = f"Wayback取得エラー: {str(e)[:60]}"
    return result
