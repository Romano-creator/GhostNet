@echo off
chcp 65001 >nul
title GhostNet

cd /d "%~dp0"

echo.
echo  ██████  ██   ██  ██████  ███████ ████████ ███    ██ ███████ ████████
echo ██       ██   ██ ██    ██ ██         ██    ████   ██ ██         ██
echo ██   ███ ███████ ██    ██ ███████    ██    ██ ██  ██ █████      ██
echo ██    ██ ██   ██ ██    ██      ██    ██    ██  ██ ██ ██         ██
echo  ██████  ██   ██  ██████  ███████    ██    ██   ████ ███████    ██
echo.
echo  Dashboard Tor + Privoxy — http://localhost:8000
echo ─────────────────────────────────────────────────────────────────────
echo.

:: Vérifie que le venv existe
if not exist "venv\Scripts\python.exe" (
    echo [ERR] venv introuvable.
    echo       Lance d'abord :
    echo         python -m venv venv
    echo         venv\Scripts\pip install fastapi uvicorn requests[socks]
    echo.
    pause
    exit /b 1
)

:: Vérifie que les dépendances sont installées
venv\Scripts\python.exe -c "import fastapi, uvicorn, requests, socks" 2>nul
if errorlevel 1 (
    echo [ERR] Dependances manquantes. Installation en cours...
    venv\Scripts\pip install fastapi uvicorn "requests[socks]"
    echo.
)

:: Vérifie que backend_v2.py existe
if not exist "backend_v2.py" (
    echo [ERR] backend_v2.py introuvable dans %cd%
    pause
    exit /b 1
)

echo [OK] Lancement de GhostNet Backend...
echo      Ouvre http://localhost:8000 dans ton navigateur
echo.
echo      Ctrl+C pour arreter
echo ─────────────────────────────────────────────────────────────────────
echo.

venv\Scripts\python.exe backend_v2.py

echo.
echo [INFO] Backend arrete.
pause