"""
GhostNet Backend v2.1 — Utilise les binaires locaux tor/ et privoxy/
Lance avec : python backend_v2.py
Dashboard  : http://localhost:8000        ← ouvre ça dans ton navigateur
API        : http://localhost:8000/status
"""

import asyncio
import time
import socket
import threading
import subprocess
import tempfile
import os
from pathlib import Path
from datetime import datetime

try:
    from fastapi import FastAPI
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.responses import JSONResponse, FileResponse, Response
    import uvicorn
    import requests
except ImportError:
    print("[ERR] Installe les dépendances : pip install fastapi uvicorn requests")
    raise SystemExit(1)

try:
    import socks  # type: ignore[import]  # noqa: F401  (PySocks — requis pour socks5h://)
except ImportError:
    print("[ERR] PySocks manquant — installe : pip install requests[socks]")
    raise SystemExit(1)

# ── CHEMINS ───────────────────────────────────────────────────────────────────
BASE         = Path(__file__).parent
TOR_EXE      = BASE / "tor"     / "tor.exe"
TOR_RC       = BASE / "tor"     / "torrc"
PRIVOXY_EXE  = BASE / "privoxy" / "privoxy.exe"
PRIVOXY_CFG  = BASE / "privoxy" / "config.txt"
LOGS_DIR     = BASE / "data"    / "logs"
COOKIE_FILE  = BASE / "data"    / "tor_data" / "control_auth_cookie"
DASHBOARD    = BASE / "tor_dashboard_v2.html"

TOR_SOCKS_PORT   = 9050
TOR_CONTROL_PORT = 9051
PRIVOXY_PORT     = 8118
BACKEND_PORT     = 8000

# ── APP ───────────────────────────────────────────────────────────────────────
app = FastAPI(title="GhostNet API", version="2.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost", "http://127.0.0.1",
                   "http://localhost:8000", "http://127.0.0.1:8000"],
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)

state_lock = threading.Lock()

state = {
    "tor_proc":      None,
    "priv_proc":     None,
    "session_start": None,
    "exit_ip":       None,
    "exit_country":  None,
    "exit_city":     None,
    "exit_org":      None,
    "transport":     "direct",
    "logs":          [],
}

_last_newnym: float = 0.0
_NEWNYM_COOLDOWN = 10.0
_fetching_tor_ip = False

# ── LOGGING ───────────────────────────────────────────────────────────────────
def log(msg: str, level: str = "info") -> None:
    ts = datetime.now().strftime("%H:%M:%S")
    entry = {"ts": ts, "msg": msg, "level": level}
    with state_lock:
        state["logs"].append(entry)
        state["logs"] = state["logs"][-300:]
    print(f"[{ts}] [{level.upper():4}] {msg}")

# ── UTILS ─────────────────────────────────────────────────────────────────────
def port_open(port: int, host: str = "127.0.0.1", timeout: float = 1.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False

async def wait_port_async(port: int, max_sec: int = 30) -> bool:
    for _ in range(max_sec):
        if port_open(port):
            return True
        await asyncio.sleep(1)
    return False

async def wait_tor_bootstrap(max_sec: int = 60) -> bool:
    log_file = LOGS_DIR / "tor.log"
    for i in range(max_sec):
        await asyncio.sleep(1)
        if log_file.exists():
            try:
                tail = log_file.read_text(encoding="utf-8", errors="replace")[-4096:]
                if "Bootstrapped 100%" in tail:
                    log(f"Tor bootstrappé à 100% ({i+1}s)", "ok")
                    return True
            except Exception:
                pass
    log("Bootstrap 100% non détecté dans le log — on tente quand même", "warn")
    return port_open(TOR_SOCKS_PORT)

def read_cookie() -> bytes | None:
    try:
        return COOKIE_FILE.read_bytes()
    except Exception as e:
        log(f"Cookie Tor introuvable : {e}", "warn")
        return None

def tor_newnym() -> bool:
    cookie = read_cookie()
    if cookie is None:
        log("Cookie d'auth Tor manquant — NEWNYM impossible", "warn")
        return False
    try:
        cookie_hex = cookie.hex()
        with socket.create_connection(("127.0.0.1", TOR_CONTROL_PORT), timeout=3) as s:
            s.sendall(f"AUTHENTICATE {cookie_hex}\r\nSIGNAL NEWNYM\r\n".encode())
            s.settimeout(2)
            try:
                resp = s.recv(1024).decode("utf-8", errors="replace")
            except socket.timeout:
                resp = ""
        if "250 OK" in resp:
            log("NEWNYM envoyé — nouveau circuit Tor", "ok")
            return True
        else:
            log(f"Réponse contrôleur Tor inattendue : {resp.strip()!r}", "warn")
            return False
    except Exception as e:
        log(f"Contrôleur Tor inaccessible : {e}", "warn")
        return False

def proxied_session() -> requests.Session:
    s = requests.Session()
    s.proxies = {
        "http":  f"socks5h://127.0.0.1:{TOR_SOCKS_PORT}",
        "https": f"socks5h://127.0.0.1:{TOR_SOCKS_PORT}",
    }
    return s

_GEO_SERVICES = [
    (
        "https://ifconfig.co/json",
        lambda d: {
            "ip":      d["ip"],
            "country": d.get("country", "?"),
            "city":    d.get("city", "?"),
            "org":     d.get("asn_org", d.get("org", "?")),
        },
    ),
    (
        "https://am.i.mullvad.net/json",
        lambda d: {
            "ip":      d["ip"],
            "country": d.get("country", "?"),
            "city":    d.get("city", "?"),
            "org":     d.get("organization", "?"),
        },
    ),
    (
        "https://ipinfo.io/json",
        lambda d: {
            "ip":      d["ip"],
            "country": d.get("country", "?"),
            "city":    d.get("city", "?"),
            "org":     d.get("org", "?"),
        },
    ),
    (
        "http://ip-api.com/json/?fields=status,message,query,country,city,org",
        lambda d: {
            "ip":      d["query"],
            "country": d.get("country", "?"),
            "city":    d.get("city", "?"),
            "org":     d.get("org", "?"),
        } if d.get("status") == "success" else (_ for _ in ()).throw(ValueError(d.get("message","ip-api error"))),
    ),
]

def fetch_ip(via_tor: bool = False) -> dict:
    sess = proxied_session() if via_tor else requests.Session()
    last_err = "Tous les services ont échoué"
    for url, parser in _GEO_SERVICES:
        try:
            resp = sess.get(url, timeout=12)
            data = resp.json()
            result = parser(data)
            if result.get("ip") and result["ip"] != "Erreur":
                return result
        except Exception as e:
            last_err = str(e)
            log(f"fetch_ip fallback ({url.split('/')[2]}) : {e}", "warn")
            continue
    return {"ip": "Erreur", "country": "?", "city": "?", "org": last_err}

def _kill_proc(proc: subprocess.Popen | None, name: str) -> None:
    if proc is None:
        return
    pid = proc.pid
    try:
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
        log(f"{name} (PID {pid}) arrêté", "warn")
    except Exception as e:
        log(f"Erreur arrêt {name} (PID {pid}) : {e}", "warn")

# ── ROUTES DASHBOARD ─────────────────────────────────────────────────────────

@app.get("/")
def serve_dashboard():
    if DASHBOARD.exists():
        return FileResponse(str(DASHBOARD), media_type="text/html")
    return JSONResponse(
        status_code=404,
        content={"error": "tor_dashboard_v2.html introuvable à côté de backend_v2.py"},
    )

@app.get("/favicon.ico", include_in_schema=False)
def favicon():
    return Response(status_code=204)

# ── ROUTES API ────────────────────────────────────────────────────────────────

@app.get("/status")
async def status():
    loop = asyncio.get_event_loop()
    tor_check, priv_check = await asyncio.gather(
        loop.run_in_executor(None, lambda: port_open(TOR_SOCKS_PORT)),
        loop.run_in_executor(None, lambda: port_open(PRIVOXY_PORT)),
    )
    with state_lock:
        sess_start   = state["session_start"]
        transport    = state["transport"]
        exit_ip      = state["exit_ip"]
        exit_country = state["exit_country"]
    return {
        "tor":           tor_check,
        "privoxy":       priv_check,
        "uptime":        int(time.time() - sess_start) if sess_start else 0,
        "transport":     transport,
        "exit_ip":       exit_ip,
        "exit_country":  exit_country,
        "tor_ready":     TOR_EXE.exists(),
        "privoxy_ready": PRIVOXY_EXE.exists(),
    }

@app.get("/logs")
def get_logs(since: int = 0):
    with state_lock:
        logs = state["logs"][since:]
    return {"logs": logs}

@app.get("/ip/real")
async def ip_real():
    log("Récupération IP réelle...", "info")
    loop = asyncio.get_event_loop()
    d = await loop.run_in_executor(None, lambda: fetch_ip(False))
    log(f"IP réelle : {d['ip']} ({d['city']}, {d['country']})", "info")
    return d

@app.get("/ip/tor")
async def ip_tor():
    if not port_open(TOR_SOCKS_PORT):
        return {"ip": "Tor non actif", "country": "?", "city": "?", "org": "?"}
    log("Récupération IP nœud de sortie Tor...", "info")
    loop = asyncio.get_event_loop()
    await loop.run_in_executor(None, _fetch_tor_ip_safe)
    with state_lock:
        return {
            "ip":      state.get("exit_ip", "?"),
            "country": state.get("exit_country", "?"),
            "city":    state.get("exit_city", "?"),
            "org":     state.get("exit_org", "?"),
        }

_tor_starting = False

def _fetch_tor_ip_safe() -> None:
    global _fetching_tor_ip
    if _fetching_tor_ip:
        log("fetch_ip Tor déjà en cours — ignoré", "info")
        return
    _fetching_tor_ip = True
    try:
        d = fetch_ip(True)
        with state_lock:
            state["exit_ip"]      = d["ip"]
            state["exit_country"] = d["country"]
            state["exit_city"]    = d.get("city", "?")
            state["exit_org"]     = d.get("org", "?")
        if d["ip"] != "Erreur":
            log(f"Nœud de sortie : {d['ip']} — {d['city']}, {d['country']}", "ok")
        else:
            log(f"fetch_ip Tor échoué : {d['org']}", "warn")
    finally:
        _fetching_tor_ip = False

@app.post("/tor/start")
async def tor_start():
    global _tor_starting
    if port_open(TOR_SOCKS_PORT):
        log("Tor déjà actif", "info")
        return {"ok": True, "msg": "Tor déjà actif"}
    if _tor_starting:
        log("Tor déjà en cours de démarrage — patience...", "info")
        return {"ok": True, "msg": "Démarrage en cours"}
    _tor_starting = True

    if not TOR_EXE.exists():
        msg = "tor.exe introuvable — lance setup.py d'abord"
        log(msg, "err")
        return JSONResponse(status_code=404, content={"ok": False, "msg": msg})

    log(f"Démarrage de Tor : {TOR_EXE}", "info")
    LOGS_DIR.mkdir(parents=True, exist_ok=True)

    try:
        proc = subprocess.Popen(
            [str(TOR_EXE), "-f", str(TOR_RC)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            cwd=str(BASE / "tor"),
        )
        with state_lock:
            state["tor_proc"] = proc

        log("Tor lancé — attente connexion (max 30s)...", "info")

        if await wait_port_async(TOR_SOCKS_PORT, max_sec=60):
            with state_lock:
                state["session_start"] = time.time()
            log("Port 9050 actif — attente bootstrap Tor...", "info")
            await wait_tor_bootstrap(max_sec=60)
            with state_lock:
                transport = state["transport"]
            if transport != "direct":
                log("Transport pluggable — attente circuits applicatifs (8s)...", "info")
                await asyncio.sleep(8)
            loop = asyncio.get_event_loop()
            loop.run_in_executor(None, _fetch_tor_ip_safe)
            _tor_starting = False
            return {"ok": True, "msg": "Tor démarré"}
        else:
            log("Timeout : Tor n'a pas répondu en 60s", "err")
            _tor_starting = False
            return JSONResponse(status_code=500,
                                content={"ok": False, "msg": "Timeout Tor"})
    except Exception as e:
        log(f"Erreur lancement Tor : {e}", "err")
        _tor_starting = False
        return JSONResponse(status_code=500, content={"ok": False, "msg": str(e)})

@app.post("/tor/stop")
def tor_stop():
    with state_lock:
        proc = state.pop("tor_proc", None)
        state["tor_proc"]      = None
        state["session_start"] = None
        state["exit_ip"]       = None
    _kill_proc(proc, "Tor")
    return {"ok": True}

@app.post("/privoxy/start")
async def privoxy_start():
    if port_open(PRIVOXY_PORT):
        log("Privoxy déjà actif", "info")
        return {"ok": True, "msg": "Privoxy déjà actif"}

    if not PRIVOXY_EXE.exists():
        msg = "privoxy.exe introuvable — lance setup.py d'abord"
        log(msg, "err")
        return JSONResponse(status_code=404, content={"ok": False, "msg": msg})

    if not port_open(TOR_SOCKS_PORT):
        log("Attention : Tor non actif — Privoxy sans tunnel Tor", "warn")

    log(f"Démarrage de Privoxy : {PRIVOXY_EXE}", "info")
    try:
        proc = subprocess.Popen(
            [str(PRIVOXY_EXE), str(PRIVOXY_CFG)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            cwd=str(BASE / "privoxy"),
        )
        with state_lock:
            state["priv_proc"] = proc

        if await wait_port_async(PRIVOXY_PORT, max_sec=10):
            log("Privoxy actif — HTTP proxy sur port 8118", "ok")
            return {"ok": True, "msg": "Privoxy démarré"}
        else:
            log("Timeout Privoxy", "err")
            return JSONResponse(status_code=500,
                                content={"ok": False, "msg": "Timeout Privoxy"})
    except Exception as e:
        log(f"Erreur lancement Privoxy : {e}", "err")
        return JSONResponse(status_code=500, content={"ok": False, "msg": str(e)})

@app.post("/privoxy/stop")
def privoxy_stop():
    with state_lock:
        proc = state["priv_proc"]
        state["priv_proc"] = None
    _kill_proc(proc, "Privoxy")
    return {"ok": True}

@app.post("/circuit/new")
async def circuit_new():
    global _last_newnym

    if not port_open(TOR_SOCKS_PORT):
        return JSONResponse(status_code=400,
                            content={"ok": False, "msg": "Tor non actif"})

    elapsed = time.time() - _last_newnym
    if elapsed < _NEWNYM_COOLDOWN:
        wait_sec = int(_NEWNYM_COOLDOWN - elapsed)
        return JSONResponse(
            status_code=429,
            content={"ok": False,
                     "msg": f"Attends encore {wait_sec}s avant un nouveau circuit"},
        )

    log("Nouveau circuit demandé...", "info")
    loop = asyncio.get_event_loop()
    success = await loop.run_in_executor(None, tor_newnym)
    if success:
        _last_newnym = time.time()
        await asyncio.sleep(5)
        loop.run_in_executor(None, _fetch_tor_ip_safe)
    return {"ok": success}

# ── CHROME LAUNCH ────────────────────────────────────────────────────────────

@app.post("/chrome/launch")
async def launch_chrome():
    """
    Lance Google Chrome avec le proxy Tor (Privoxy)
    Crée un profil temporaire pour ne pas mélanger avec le Chrome normal
    """
    # Vérifier que Tor et Privoxy sont actifs
    if not port_open(TOR_SOCKS_PORT):
        return JSONResponse(
            status_code=400,
            content={"ok": False, "msg": "Tor n'est pas actif"}
        )
    
    if not port_open(PRIVOXY_PORT):
        return JSONResponse(
            status_code=400,
            content={"ok": False, "msg": "Privoxy n'est pas actif"}
        )
    
    # Chemins possibles pour Chrome
    chrome_paths = [
        "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
        "C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe",
        os.path.expanduser("~\\AppData\\Local\\Google\\Chrome\\Application\\chrome.exe"),
    ]
    
    chrome_exe = None
    for path in chrome_paths:
        if os.path.exists(path):
            chrome_exe = path
            break
    
    if not chrome_exe:
        return JSONResponse(
            status_code=404,
            content={"ok": False, "msg": "Chrome introuvable sur le système"}
        )
    
    # Créer un dossier temporaire pour le profil Chrome
    temp_profile = tempfile.mkdtemp(prefix="chrome_tor_")
    
    # Commande pour lancer Chrome avec proxy
    cmd = [
        chrome_exe,
        f"--proxy-server=http://127.0.0.1:{PRIVOXY_PORT}",
        f"--user-data-dir={temp_profile}",
        "--new-window",
        "https://check.torproject.org/",
    ]
    
    try:
        # Lancer Chrome en arrière-plan
        subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0
        )
        log(f"Chrome lancé avec proxy Tor (profil: {temp_profile})", "ok")
        return {"ok": True, "msg": "Chrome lancé avec proxy Tor", "profile": temp_profile}
    except Exception as e:
        log(f"Erreur lancement Chrome: {e}", "err")
        return JSONResponse(
            status_code=500,
            content={"ok": False, "msg": str(e)}
        )

# ── BRIDGES ──────────────────────────────────────────────────────────────────
BRIDGES: dict[str, list[str]] = {
    "obfs4": [
        "obfs4 76.70.53.5:9856 B7A1DCB550B0C4EFB21932F9A92D56CD7A77502B cert=7SEwtm0wHlE7MCgLa95X8rPrzzW1QJRg4cpXh2c63kf4lJ5h4hVoNkk2J/z1qUiT+jFfEA iat-mode=0",
        "obfs4 76.70.53.139:9856 B7A1DCB550B0C4EFB21932F9A92D56CD7A77502B cert=7SEwtm0wHlE7MCgLa95X8rPrzzW1QJRg4cpXh2c63kf4lJ5h4hVoNkk2J/z1qUiT+jFfEA iat-mode=0",
        "obfs4 [2a0a:4587:2012:1::251]:11251 BDE1BBC62DB8EBAE17EEF369A7271512C8B29D0F cert=uG0DsVlVpmb11kIU6HoKsOphEkdpWYfoAnxUh0Z9AGL7kDVxgLTquKS5VUWaS/tijZykJA iat-mode=0",
        "obfs4 [2003:d0:af44:c100:be24:11ff:fe1b:dfd2]:512 B2C717B2D1CF4E6F3D05E998C936EAEC4E7DC706 cert=xQ1KEMVmT8XZQHF3X2qZpfJic2di8SAiblx1fwLh1l9kw/RNI+wnxILgAy7zcQ2Mbl95UA iat-mode=0",
    ],
}

@app.post("/transport/{name}")
def set_transport(name: str):
    valid = ["direct", "obfs4", "meek-azure", "snowflake", "WebTunnel"]
    if name not in valid:
        return JSONResponse(
            status_code=400,
            content={"ok": False, "msg": f"Transport invalide — valeurs : {valid}"},
        )

    if name != "direct" and name not in BRIDGES:
        msg = f"Aucun bridge {name} configuré — ajoute-les dans BRIDGES dans backend_v2.py"
        log(msg, "err")
        return JSONResponse(status_code=400, content={"ok": False, "msg": msg})

    with state_lock:
        state["transport"] = name

    if TOR_RC.exists():
        rc = TOR_RC.read_text(encoding="utf-8")
        if name == "direct":
            rc = _torrc_set_bridges(rc, [], use_bridges=False)
            log("Transport désactivé — Tor direct", "warn")
        else:
            bridges = BRIDGES[name]
            rc = _torrc_set_bridges(rc, bridges, use_bridges=True)
            log(f"Transport {name} configuré — {len(bridges)} bridge(s) écrits dans torrc", "ok")
        TOR_RC.write_text(rc, encoding="utf-8")

    return {"ok": True, "transport": name}

def _torrc_set(content: str, key: str, value: str) -> str:
    import re
    pattern = rf"^#?\s*{re.escape(key)}\s+.*$"
    replacement = f"{key} {value}"
    new_content = re.sub(pattern, replacement, content, flags=re.MULTILINE)
    if replacement not in new_content:
        new_content += f"\n{replacement}\n"
    return new_content

def _torrc_set_bridges(content: str, bridges: list[str], use_bridges: bool) -> str:
    import re
    content = re.sub(r"^#?\s*Bridge\s+.*$", "", content, flags=re.MULTILINE)
    content = _torrc_set(content, "UseBridges", "1" if use_bridges else "0")
    content = re.sub(r"\n{3,}", "\n\n", content).rstrip() + "\n"
    if use_bridges and bridges:
        content += "\n" + "\n".join(f"Bridge {b}" for b in bridges) + "\n"
    return content

# ── AUTO-CORRECTION DES CHEMINS ──────────────────────────────────────────────

def _fix_config_paths() -> None:
    """
    Vérifie que torrc et config.txt contiennent des chemins qui correspondent
    à l'emplacement actuel du dossier GhostNet.
    Si le projet a été déplacé depuis le dernier setup.py, les corrige automatiquement.
    """
    _fix_torrc_paths()
    _fix_privoxy_paths()

def _fix_torrc_paths() -> None:
    if not TOR_RC.exists():
        return
    content = TOR_RC.read_text(encoding="utf-8")
    tor_data = BASE / "data" / "tor_data"
    cookie   = tor_data / "control_auth_cookie"
    log_file = BASE / "data" / "logs" / "tor.log"
    obfs4    = BASE / "tor" / "lyrebird.exe"

    # Construit les lignes attendues avec les chemins actuels
    expected = {
        "CookieAuthFile": cookie.as_posix(),
        "DataDirectory":  tor_data.as_posix(),
        "Log":            f"notice file {log_file.as_posix()}",
    }
    if obfs4.exists():
        expected["ClientTransportPlugin"] = f"obfs4 exec {obfs4.as_posix()}"

    changed = False
    import re
    new_content = content
    for key, value in expected.items():
        pattern = rf"^({re.escape(key)}\s+).*$"
        replacement = f"{key} {value}"
        updated = re.sub(pattern, replacement, new_content, flags=re.MULTILINE)
        if updated != new_content:
            changed = True
            new_content = updated

    if changed:
        TOR_RC.write_text(new_content, encoding="utf-8")
        log("torrc : chemins mis à jour vers l'emplacement actuel", "ok")
    else:
        log("torrc : chemins OK", "info")

def _fix_privoxy_paths() -> None:
    if not PRIVOXY_CFG.exists():
        return
    content = PRIVOXY_CFG.read_text(encoding="utf-8")
    log_dir  = (BASE / "data" / "logs").as_posix()

    import re
    new_content = re.sub(
        r"^(logdir\s+).*$",
        f"logdir {log_dir}",
        content,
        flags=re.MULTILINE,
    )
    if new_content != content:
        PRIVOXY_CFG.write_text(new_content, encoding="utf-8")
        log("config.txt Privoxy : chemin logdir mis à jour", "ok")
    else:
        log("config.txt Privoxy : chemins OK", "info")

# ── MAIN ──────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    log("GhostNet Backend v2.1 démarré", "info")
    log(f">>> Ouvre http://localhost:{BACKEND_PORT} dans ton navigateur <<<", "ok")
    if not TOR_EXE.exists():
        log("tor.exe manquant — lance setup.py d'abord !", "err")
    if not PRIVOXY_EXE.exists():
        log("privoxy.exe manquant — lance setup.py d'abord !", "err")
    # FIX : corrige automatiquement les chemins absolus si le dossier a été déplacé
    _fix_config_paths()
    uvicorn.run(app, host="127.0.0.1", port=BACKEND_PORT, log_level="warning")