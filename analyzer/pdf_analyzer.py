"""
PDFテキスト抽出モジュール（OCRフォールバック付き）
"""

from typing import Tuple


def extract_pdf_text(file_bytes: bytes) -> Tuple[str, str]:
    """
    PDFバイト列からテキストを抽出。
    通常テキストPDF → pdfplumber
    画像PDF（0文字）→ pymupdf + pytesseract OCR にフォールバック
    """
    # ── まず通常のテキスト抽出を試みる ──
    try:
        import pdfplumber
        import io
        with pdfplumber.open(io.BytesIO(file_bytes)) as pdf:
            pages = []
            for i, page in enumerate(pdf.pages):
                if i >= 60:
                    break
                text = page.extract_text()
                if text:
                    pages.append(text)
            normal_text = "\n\n".join(pages)
    except Exception as e:
        normal_text = ""

    # テキストが取れていれば返す
    if len(normal_text.strip()) > 50:
        return normal_text, ""

    # ── 画像PDFのためOCRにフォールバック ──
    return _ocr_pdf(file_bytes)


def _ocr_pdf(file_bytes: bytes) -> Tuple[str, str]:
    """pymupdf + pytesseract でOCR"""
    try:
        import fitz          # pymupdf
        import pytesseract
        from PIL import Image
        import io

        doc = fitz.open(stream=file_bytes, filetype="pdf")
        total_pages = doc.page_count
        max_pages = min(total_pages, 30)  # 処理上限30ページ

        results = []
        for i in range(max_pages):
            page = doc[i]
            # 150dpiで画像レンダリング（速度優先）
            mat = fitz.Matrix(150 / 72, 150 / 72)
            pix = page.get_pixmap(matrix=mat)
            img = Image.frombytes("RGB", [pix.width, pix.height], pix.samples)

            # 日本語 + 英語 OCR
            text = pytesseract.image_to_string(img, lang="jpn+eng")
            if text.strip():
                results.append(f"[ページ{i+1}]\n{text.strip()}")

        doc.close()

        if not results:
            return "", "OCRでもテキストを抽出できませんでした（画像が低解像度または暗号化されている可能性）"

        suffix = f"\n\n※ 全{total_pages}ページ中{max_pages}ページをOCR処理しました。" if total_pages > max_pages else ""
        return "\n\n".join(results) + suffix, ""

    except ImportError as e:
        return "", f"OCRライブラリが未インストール: {e}"
    except Exception as e:
        return "", f"OCRエラー: {str(e)[:100]}"
