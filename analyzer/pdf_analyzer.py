"""
PDFテキスト抽出モジュール
"""

from typing import Tuple

def extract_pdf_text(file_bytes: bytes) -> Tuple[str, str]:
    """PDFバイト列からテキストを抽出。(text, error)を返す"""
    try:
        import pdfplumber
        import io
        with pdfplumber.open(io.BytesIO(file_bytes)) as pdf:
            pages = []
            for i, page in enumerate(pdf.pages):
                if i >= 50:  # 最大50ページ
                    break
                text = page.extract_text()
                if text:
                    pages.append(text)
            return "\n\n".join(pages), ""
    except ImportError:
        return "", "pdfplumberが未インストール（pip install pdfplumber）"
    except Exception as e:
        return "", f"PDF解析エラー: {str(e)[:80]}"
