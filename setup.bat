@echo off
echo === 詐欺・ポンジ調査ツール セットアップ ===
echo.

REM Python確認
python --version 2>nul
if errorlevel 1 (
    echo [ERROR] Pythonがインストールされていません。
    echo https://www.python.org/ からインストールしてください。
    pause
    exit /b 1
)

REM 仮想環境作成
if not exist ".venv" (
    echo 仮想環境を作成中...
    python -m venv .venv
)

REM 依存関係インストール
echo 依存ライブラリをインストール中...
.venv\Scripts\pip install -r requirements.txt

echo.
echo セットアップ完了！ run.bat でアプリを起動してください。
pause
