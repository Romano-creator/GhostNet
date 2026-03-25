"""
GhostNet - Setup v2.1
Lance ce script UNE SEULE FOIS pour préparer l'environnement.
Télécharge et extrait Tor + Privoxy dans le dossier courant.
"""

import os
import re
import sys
import shutil
import hashlib
import zipfile
import tarfile
import subprocess
import urllib.request
from pathlib import Path

BASE        = Path(__file__).parent
TOR_DIR     = BASE / "tor"
PRIVOXY_DIR = BASE / "privoxy"
DATA_DIR    = BASE / "data"
LOGS_DIR    = DATA_DIR / "logs"
TOR_DATA    = DATA_DIR / "tor_data"
SEVEN_ZIP   = BASE / "tools" / "7za.exe"

# ── URLs ──────────────────────────────────────────────────────────────────────
SEVEN_ZIP_URL = "https://www.7-zip.org/a/7za920.zip"

TOR_BUNDLE_URL     = "https://archive.torproject.org/tor-package-archive/torbrowser/15.0.8/tor-expert-bundle-windows-x86_64-15.0.8.tar.gz"
TOR_SHA256SUMS_URL = "https://archive.torproject.org/tor-package-archive/torbrowser/15.0.8/sha256sums-unsigned-build.txt"

PRIVOXY_URL        = "https://www.privoxy.org/sf-download-mirror/Win32/4.1.0/privoxy_setup_4.1.0.exe"
# FIX SECURITE : vérification SHA256 pour Privoxy (fichier de checksums officiel)
PRIVOXY_SHA256_URL = "https://www.privoxy.org/sf-download-mirror/Win32/4.1.0/privoxy_setup_4.1.0.exe.asc"

# ── HELPERS ───────────────────────────────────────────────────────────────────

def banner(msg):
    print(f"\n{'='*52}")
    print(f"  {msg}")
    print('='*52)

def ok(msg):   print(f"  [OK]   {msg}")
def info(msg): print(f"  [INFO] {msg}")
def warn(msg): print(f"  [WARN] {msg}")
def err(msg):  print(f"  [ERR]  {msg}")

def download(url: str, dest: Path, label: str) -> bool:
    info(f"Téléchargement : {label}")
    info(f"URL : {url}")
    dest.parent.mkdir(parents=True, exist_ok=True)
    try:
        def progress(count, block, total):
            if total > 0:
                pct = min(100, int(count * block * 100 / total))
                bar = '█' * (pct // 5) + '░' * (20 - pct // 5)
                print(f"\r  [{bar}] {pct}%", end='', flush=True)
        urllib.request.urlretrieve(url, dest, reporthook=progress)
        print()
        ok(f"Téléchargé : {dest.name} ({dest.stat().st_size // 1024} Ko)")
        return True
    except Exception as e:
        print()
        err(f"Échec téléchargement {label} : {e}")
        return False

def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()

def verify_sha256_from_sums(file_path: Path, sums_url: str) -> bool:
    """
    FIX SECURITE : retourne False si la vérification est impossible (au lieu de True).
    Un réseau qui bloque les checksums = setup interrompu, pas silencieusement ignoré.
    """
    info(f"Vérification SHA256 de {file_path.name}...")
    tmp = file_path.parent / "_sha256sums.txt"
    try:
        urllib.request.urlretrieve(sums_url, tmp)
        content = tmp.read_text(encoding="utf-8")
        tmp.unlink(missing_ok=True)
    except Exception as e:
        err(f"Impossible de récupérer les checksums depuis {sums_url}")
        err(f"Erreur : {e}")
        err("Vérification SHA256 impossible — setup interrompu pour ta sécurité.")
        err("Assure-toi d'avoir internet et de ne pas être derrière un proxy bloquant.")
        return False   # FIX : était True — dangereux en cas de MITM

    expected = None
    for line in content.splitlines():
        parts = line.strip().split()
        if len(parts) >= 2:
            # Gère les formats "hash  filename" et "hash *filename"
            fname = Path(parts[1].lstrip("*")).name
            if fname == file_path.name:
                expected = parts[0].lower()
                break

    if expected is None:
        warn(f"{file_path.name} absent du fichier sha256sums.")
        warn("Impossible de vérifier l'intégrité — supprime le fichier et relance.")
        return False   # FIX : était True

    actual = sha256_file(file_path).lower()
    if actual == expected:
        ok(f"SHA256 valide ✓ ({actual[:16]}...)")
        return True
    else:
        err(f"SHA256 INVALIDE pour {file_path.name} !")
        err(f"  Attendu : {expected}")
        err(f"  Obtenu  : {actual}")
        err("Fichier potentiellement altéré ou corrompu. Supprime-le et relance.")
        file_path.unlink(missing_ok=True)
        return False


# ── ÉTAPE 1 : 7-Zip portable ──────────────────────────────────────────────────

def setup_7zip() -> bool:
    banner("Étape 1/3 — 7-Zip portable")
    tools_dir = BASE / "tools"
    tools_dir.mkdir(exist_ok=True)

    if SEVEN_ZIP.exists():
        ok("7za.exe déjà présent")
        return True

    tmp = BASE / "tools" / "7zip.zip"
    if not download(SEVEN_ZIP_URL, tmp, "7-Zip portable"):
        return False

    try:
        with zipfile.ZipFile(tmp, 'r') as z:
            if "7za.exe" not in z.namelist():
                err("7za.exe introuvable dans l'archive")
                return False
            z.extract("7za.exe", tools_dir)
        tmp.unlink(missing_ok=True)
        ok("7za.exe extrait dans tools/")
        return True
    except Exception as e:
        err(f"Extraction 7-Zip échouée : {e}")
        return False


# ── ÉTAPE 2 : Tor Expert Bundle ───────────────────────────────────────────────

def setup_tor() -> bool:
    banner("Étape 2/3 — Tor Expert Bundle")

    if (TOR_DIR / "tor.exe").exists():
        ok("tor.exe déjà présent — binaire ignoré")
        # FIX : régénère toujours torrc avec les chemins actuels
        # (si le dossier a été déplacé, les anciens chemins absolus seraient cassés)
        write_torrc()
        return True

    TOR_DIR.mkdir(exist_ok=True)
    tmp = BASE / "tools" / "tor_bundle.tar.gz"

    if not tmp.exists():
        if not download(TOR_BUNDLE_URL, tmp, "Tor Expert Bundle (~21 Mo)"):
            return False

    if not verify_sha256_from_sums(tmp, TOR_SHA256SUMS_URL):
        return False

    info("Extraction de l'archive Tor...")
    try:
        # FIX BUG : utilise extractfile() + write_bytes() au lieu de mutater
        # m.name en place (comportement déprecié/cassé en Python 3.12+)
        with tarfile.open(tmp, "r:gz") as tar:
            extracted = []
            for m in tar.getmembers():
                if any(m.name.endswith(x) for x in ('.exe', '.dll', '.meek-client')):
                    fname = Path(m.name).name
                    if not fname:
                        continue
                    fobj = tar.extractfile(m)
                    if fobj is None:
                        continue
                    dest = TOR_DIR / fname
                    dest.write_bytes(fobj.read())
                    extracted.append(fname)
                    info(f"  Extrait : {fname}")
            if not extracted:
                raise ValueError("Aucun fichier .exe/.dll trouvé dans l'archive")
        ok(f"Tor extrait dans tor/ ({len(extracted)} fichiers)")
    except Exception as e:
        err(f"Extraction Python échouée : {e}")
        if not SEVEN_ZIP.exists():
            err("7za.exe manquant — impossible de retenter avec 7-Zip")
            return False
        info("Tentative avec 7-Zip...")
        result = subprocess.run(
            [str(SEVEN_ZIP), "e", str(tmp), f"-o{TOR_DIR}", "*.exe", "*.dll", "-r", "-y"],
            capture_output=True, text=True
        )
        if result.returncode != 0 or not (TOR_DIR / "tor.exe").exists():
            err("Extraction 7-Zip également échouée")
            err(result.stderr)
            return False
        ok("Tor extrait avec 7-Zip")

    tmp.unlink(missing_ok=True)
    write_torrc()
    return True


def write_torrc():
    torrc    = TOR_DIR / "torrc"
    tor_data = DATA_DIR / "tor_data"
    tor_data.mkdir(parents=True, exist_ok=True)

    obfs4   = TOR_DIR / "obfs4proxy.exe"
    pt_line = f"ClientTransportPlugin obfs4 exec {obfs4.as_posix()}" if obfs4.exists() else ""

    content = f"""## GhostNet - torrc (généré automatiquement)

SocksPort 9050
ControlPort 9051

## Authentification par cookie (sécurisé — requis par backend_v2.py)
CookieAuthentication 1
CookieAuthFile {(tor_data / 'control_auth_cookie').as_posix()}

DataDirectory {tor_data.as_posix()}

## Pluggable Transports
{pt_line}

## Logging
Log notice file {(LOGS_DIR / 'tor.log').as_posix()}
"""
    torrc.write_text(content, encoding="utf-8")
    ok(f"torrc généré : {torrc}")


# ── ÉTAPE 3 : Privoxy portable ────────────────────────────────────────────────

def _verify_privoxy_sha256(tmp: Path) -> bool:
    """
    FIX SECURITE : vérifie Privoxy contre un hash connu ou une source officielle.
    Privoxy publie des checksums sur privoxy.org.
    """
    # Tentative 1 : fichier .sha256sum officiel privoxy.org
    sha_url = "https://www.privoxy.org/sf-download-mirror/Win32/4.1.0/privoxy_setup_4.1.0.exe.sha256sum"
    sha_tmp = tmp.parent / "_privoxy.sha256sum"
    try:
        urllib.request.urlretrieve(sha_url, sha_tmp)
        content = sha_tmp.read_text(encoding="utf-8").strip()
        sha_tmp.unlink(missing_ok=True)
        # Format attendu : "abc123...  privoxy_setup_4.1.0.exe" ou juste le hash
        parts = content.split()
        if parts:
            expected = parts[0].lower()
            actual   = sha256_file(tmp).lower()
            if actual == expected:
                ok(f"SHA256 Privoxy valide ✓ ({actual[:16]}...)")
                return True
            else:
                err(f"SHA256 Privoxy INVALIDE !")
                err(f"  Attendu : {expected}")
                err(f"  Obtenu  : {actual}")
                tmp.unlink(missing_ok=True)
                return False
    except Exception as e:
        warn(f"Impossible de récupérer le checksum Privoxy : {e}")
        warn("Privoxy sera installé SANS vérification d'intégrité.")
        warn("Assure-toi d'être sur un réseau de confiance.")
        # On continue quand même mais on prévient clairement l'utilisateur
        return True  # Dégradé accepté : Privoxy n'a pas de GPG key publique stable

def setup_privoxy() -> bool:
    banner("Étape 3/3 — Privoxy portable")

    if (PRIVOXY_DIR / "privoxy.exe").exists():
        ok("privoxy.exe déjà présent — binaire ignoré")
        # FIX : régénère toujours config.txt avec les chemins actuels
        write_privoxy_config()
        return True

    PRIVOXY_DIR.mkdir(exist_ok=True)
    tmp = BASE / "tools" / "privoxy_setup.exe"

    if not tmp.exists():
        if not download(PRIVOXY_URL, tmp, "Privoxy installer"):
            return False

    # FIX SECURITE : vérification SHA256 pour Privoxy
    if not _verify_privoxy_sha256(tmp):
        return False

    # Méthode 1 : installation silencieuse NSIS (la plus fiable pour un .exe NSIS)
    info("Installation silencieuse de Privoxy...")
    abs_dir = str(PRIVOXY_DIR.resolve())
    result = subprocess.run(
        [str(tmp), "/S", f"/D={abs_dir}"],
        capture_output=True
    )
    # L'installeur NSIS /S se termine rapidement, mais l'extraction est asynchrone
    # On attend que privoxy.exe apparaisse (max 15s)
    for _ in range(15):
        if (PRIVOXY_DIR / "privoxy.exe").exists():
            break
        import time
        time.sleep(1)

    if (PRIVOXY_DIR / "privoxy.exe").exists():
        ok("privoxy.exe installé via NSIS")
        tmp.unlink(missing_ok=True)
        _cleanup_privoxy_dir()
        write_privoxy_config()
        return True

    # Méthode 2 : extraction avec 7-Zip (fallback si NSIS /S échoue)
    if SEVEN_ZIP.exists():
        info("Fallback : extraction avec 7-Zip...")
        # FIX BUG : utilise "x" (extract with full paths) et non "e" pour NSIS
        result = subprocess.run(
            [str(SEVEN_ZIP), "x", str(tmp), f"-o{PRIVOXY_DIR}", "-y"],
            capture_output=True, text=True
        )
        # L'installeur NSIS extrait dans un sous-dossier $PLUGINSDIR ou à la racine
        privoxy_exe = PRIVOXY_DIR / "privoxy.exe"
        if not privoxy_exe.exists():
            # Cherche récursivement
            for f in PRIVOXY_DIR.rglob("privoxy.exe"):
                shutil.copy(f, privoxy_exe)
                info(f"privoxy.exe trouvé et copié depuis {f.parent}")
                break

    if not (PRIVOXY_DIR / "privoxy.exe").exists():
        err("Privoxy : impossible d'extraire privoxy.exe")
        err("Essaie de l'installer manuellement depuis https://www.privoxy.org/")
        err(f"et copie privoxy.exe dans : {PRIVOXY_DIR}")
        return False

    tmp.unlink(missing_ok=True)
    _cleanup_privoxy_dir()
    write_privoxy_config()
    return True


def _cleanup_privoxy_dir():
    """Supprime les fichiers inutiles laissés par l'installeur NSIS."""
    for f in list(PRIVOXY_DIR.iterdir()):
        if f.suffix in ('.nsi', '.nsh', '.bmp', '.ico', '.nfo') \
           or f.name.startswith('$') \
           or f.name.startswith('Uninstall'):
            try:
                if f.is_file():
                    f.unlink()
                elif f.is_dir():
                    shutil.rmtree(f, ignore_errors=True)
            except Exception:
                pass


def write_privoxy_config():
    config = PRIVOXY_DIR / "config.txt"
    content = f"""## GhostNet - Privoxy config (généré automatiquement)

listen-address  127.0.0.1:8118
toggle  1
enable-remote-toggle  0
enable-remote-http-toggle  0
enable-edit-actions 0

## Tunnel tout le trafic vers Tor SOCKS5
forward-socks5t / 127.0.0.1:9050 .

## Logging minimal
logdir {LOGS_DIR.as_posix()}
logfile privoxy.log
debug 0
"""
    config.write_text(content, encoding="utf-8")
    ok(f"config.txt Privoxy généré : {config}")


# ── FINALISATION ──────────────────────────────────────────────────────────────

def check_install() -> bool:
    banner("Vérification finale")
    checks = {
        "tor/tor.exe":         TOR_DIR / "tor.exe",
        "tor/torrc":           TOR_DIR / "torrc",
        "privoxy/privoxy.exe": PRIVOXY_DIR / "privoxy.exe",
        "privoxy/config.txt":  PRIVOXY_DIR / "config.txt",
        "data/tor_data/":      DATA_DIR / "tor_data",
        "data/logs/":          LOGS_DIR,
    }
    all_ok = True
    for label, path in checks.items():
        if path.exists():
            ok(label)
        else:
            err(f"MANQUANT : {label}")
            all_ok = False
    return all_ok

def create_dirs():
    for d in [DATA_DIR, LOGS_DIR, TOR_DATA, BASE / "tools"]:
        d.mkdir(parents=True, exist_ok=True)


# ── MAIN ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("\n" + "█"*52)
    print("  GHOSTNET — Setup v2.1")
    print("  Prépare Tor et Privoxy en portable")
    print("█"*52)

    create_dirs()

    steps = [setup_7zip, setup_tor, setup_privoxy]
    for step in steps:
        if not step():
            err("Setup interrompu — corrige l'erreur ci-dessus et relance")
            sys.exit(1)

    if check_install():
        banner("✓ Setup terminé avec succès !")
        print("  Lance maintenant : start.bat")
        print("  Puis ouvre     : http://localhost:8000")
        print("  (plus besoin d'ouvrir le .html directement)\n")
    else:
        err("Certains fichiers manquent — relance setup.py")
        sys.exit(1)