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
    # Bande passante (mise à jour par BandwidthMonitor)
    "bw_down":       0,   # octets/s download (dernier event)
    "bw_up":         0,   # octets/s upload   (dernier event)
    "bw_total_down": 0,   # total session download
    "bw_total_up":   0,   # total session upload
}

_last_newnym: float = 0.0
_NEWNYM_COOLDOWN = 10.0
_fetching_tor_ip = False
_flags_lock = threading.Lock()   # protège _fetching_tor_ip et _tor_starting
# Auto-rotation
_autorotate_task: asyncio.Task | None = None
_autorotate_interval: int = 0  # 0 = désactivé, sinon secondes entre chaque NEWNYM

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
        } if d.get("status") == "success" else (_ for _ in ()).throw(ValueError(d.get("message", "ip-api error"))),
    ),
]

# Timeout par service (secondes) — réduit pour ne pas bloquer trop longtemps
_GEO_TIMEOUT = 8

def _fetch_one_geo(url: str, parser, sess: requests.Session) -> dict | None:
    """Tente un seul service géo. Retourne None en cas d'échec."""
    try:
        resp = sess.get(url, timeout=_GEO_TIMEOUT)
        data = resp.json()
        result = parser(data)
        if result.get("ip") and result["ip"] != "Erreur":
            return result
    except Exception:
        pass
    return None

def fetch_ip(via_tor: bool = False) -> dict:
    """
    Interroge tous les services géo EN PARALLÈLE et retourne le premier
    qui répond. Timeout global = _GEO_TIMEOUT + 1s.
    Évite d'attendre 4×timeout en cas de nœud de sortie lent.
    """
    import concurrent.futures
    sess = proxied_session() if via_tor else requests.Session()

    with concurrent.futures.ThreadPoolExecutor(max_workers=len(_GEO_SERVICES)) as pool:
        futures = {
            pool.submit(_fetch_one_geo, url, parser, sess): url.split("/")[2]
            for url, parser in _GEO_SERVICES
        }
        for future in concurrent.futures.as_completed(
            futures, timeout=_GEO_TIMEOUT + 1
        ):
            result = future.result()
            if result is not None:
                # Annule les autres requêtes en cours (best-effort)
                for f in futures:
                    f.cancel()
                return result

    log("fetch_ip : tous les services géo ont échoué ou timeout", "warn")
    return {"ip": "Erreur", "country": "?", "city": "?", "org": "Tous les services ont timeout"}

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
    with _flags_lock:
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
            log(f"Nœud de sortie : {d['ip']} — {d.get('city','?')}, {d['country']}", "ok")
        else:
            log(f"IP nœud de sortie indisponible — {d['org']}", "warn")
    finally:
        with _flags_lock:
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
            bw_monitor.start()   # ← démarre la lecture bande passante
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
    global _autorotate_task, _autorotate_interval
    bw_monitor.stop()
    if _autorotate_task and not _autorotate_task.done():
        _autorotate_task.cancel()
    _autorotate_task = None
    _autorotate_interval = 0
    with state_lock:
        proc = state.pop("tor_proc", None)
        state["tor_proc"]      = None
        state["session_start"] = None
        state["exit_ip"]       = None
        state["bw_down"]       = 0
        state["bw_up"]         = 0
        state["bw_total_down"] = 0
        state["bw_total_up"]   = 0
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
# Bridges de secours — utilisés si le fetch en ligne échoue
_FALLBACK_BRIDGES: dict[str, list[str]] = {
    "obfs4": [
        "obfs4 [2a04:dd00:26:9:216:3cff:fe7c:a50e]:31337 E315A7F8A5E2C1B4819D09D79C5A627D65C182AB cert=uFpKPZe/wmdL4o+mGABkhUSh33w457bfY3r+D93o0bzda+NpdAkkr87dUkzihagV61WIOA iat-mode=0",
        "obfs4 [2a04:dd01:19:81:195:242:99:71]:31337 E315A7F8A5E2C1B4819D09D79C5A627D65C182AB cert=uFpKPZe/wmdL4o+mGABkhUSh33w457bfY3r+D93o0bzda+NpdAkkr87dUkzihagV61WIOA iat-mode=0",
    ],
}

BRIDGES: dict[str, list[str]] = dict(_FALLBACK_BRIDGES)  # sera mis à jour au démarrage

# Sources pour récupérer des bridges obfs4 frais
# Chaque source est un (url, parser) — parser reçoit le texte brut et retourne une liste de strings "obfs4 ..."
_BRIDGE_SOURCES = [
    # API bridges.torproject.org — retourne des bridges directement
    (
        "https://bridges.torproject.org/bridges?transport=obfs4",
        lambda text: [
            line.strip()
            for line in text.splitlines()
            if line.strip().startswith("obfs4 ")
        ],
    ),
    # Collecteur communautaire de bridges Tor (mis à jour régulièrement)
    (
        "https://raw.githubusercontent.com/scriptzteam/Tor-Bridges-Collector/main/obfs4",
        lambda text: [
            line.strip()
            for line in text.splitlines()
            if line.strip().startswith("obfs4 ")
        ],
    ),
]


def fetch_bridges_online() -> dict[str, list[str]]:
    """
    Tente de récupérer des bridges obfs4 frais depuis les sources officielles Tor.
    Retourne un dict compatible avec BRIDGES, ou un dict vide si tout échoue.
    """
    import concurrent.futures

    results: list[str] = []

    def _try_source(url: str, parser) -> list[str]:
        try:
            resp = requests.get(url, timeout=10, headers={"User-Agent": "GhostNet/2.1"})
            resp.raise_for_status()
            parsed = parser(resp.text)
            if parsed:
                log(f"Bridges récupérés depuis {url.split('/')[2]} : {len(parsed)} bridge(s)", "ok")
            return parsed
        except Exception as e:
            log(f"Source bridges {url.split('/')[2]} inaccessible : {e}", "warn")
            return []

    with concurrent.futures.ThreadPoolExecutor(max_workers=len(_BRIDGE_SOURCES)) as pool:
        futures = [pool.submit(_try_source, url, parser) for url, parser in _BRIDGE_SOURCES]
        for future in concurrent.futures.as_completed(futures, timeout=12):
            bridges = future.result()
            for b in bridges:
                if b not in results:
                    results.append(b)

    if results:
        return {"obfs4": results}
    return {}


def refresh_bridges() -> bool:
    """
    Met à jour BRIDGES avec des bridges frais.
    Retourne True si au moins un nouveau bridge a été trouvé.
    """
    global BRIDGES
    log("Recherche de bridges obfs4 frais...", "info")
    fresh = fetch_bridges_online()
    if fresh.get("obfs4"):
        BRIDGES = fresh
        log(f"BRIDGES mis à jour : {len(fresh['obfs4'])} bridge(s) obfs4 actifs", "ok")
        return True
    else:
        log("Aucun bridge frais trouvé — bridges de secours conservés", "warn")
        BRIDGES = dict(_FALLBACK_BRIDGES)
        return False


@app.post("/bridges/refresh")
async def api_bridges_refresh():
    """Relance le fetch des bridges depuis les sources Tor. Utile si les bridges ne fonctionnent plus."""
    loop = asyncio.get_event_loop()
    success = await loop.run_in_executor(None, refresh_bridges)
    with state_lock:
        transport = state["transport"]
    # Si un transport pluggable est actif, réécrit le torrc avec les nouveaux bridges
    if success and transport != "direct" and transport in BRIDGES and TOR_RC.exists():
        rc = TOR_RC.read_text(encoding="utf-8")
        rc = _torrc_set_bridges(rc, BRIDGES[transport], use_bridges=True)
        TOR_RC.write_text(rc, encoding="utf-8")
        log("torrc mis à jour avec les nouveaux bridges", "ok")
    return {
        "ok": success,
        "bridges": BRIDGES.get("obfs4", []),
        "count": len(BRIDGES.get("obfs4", [])),
        "msg": f"{len(BRIDGES.get('obfs4', []))} bridge(s) disponibles",
    }


@app.get("/bridges/list")
def api_bridges_list():
    """Retourne les bridges actuellement en mémoire."""
    return {
        "bridges": BRIDGES,
        "source": "live" if BRIDGES != _FALLBACK_BRIDGES else "fallback",
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
    # Supprime les lignes "Bridge obfs4 ..." ET les lignes "obfs4 ..." sans préfixe
    content = re.sub(r"^#?\s*(?:Bridge\s+)?(?:obfs4|meek|snowflake|webtunnel)\s+.*$", "", content, flags=re.MULTILINE | re.IGNORECASE)
    content = _torrc_set(content, "UseBridges", "1" if use_bridges else "0")
    content = re.sub(r"\n{3,}", "\n\n", content).rstrip() + "\n"
    if use_bridges and bridges:
        content += "\n" + "\n".join(f"Bridge {b}" for b in bridges) + "\n"
    return content

# ── BANDWIDTH MONITOR ────────────────────────────────────────────────────────

class BandwidthMonitor:
    """
    Maintient une connexion persistante au Control Port Tor et lit les events
    '650 BW <down> <up>' en temps réel pour alimenter state["bw_*"].
    Se reconnecte automatiquement si la connexion est perdue.
    """
    def __init__(self):
        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()

    def start(self):
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run, daemon=True, name="bw-monitor")
        self._thread.start()
        log("BandwidthMonitor démarré", "info")

    def stop(self):
        self._stop_event.set()
        # Remet les stats à zéro
        with state_lock:
            state["bw_down"] = 0
            state["bw_up"]   = 0

    def _run(self):
        while not self._stop_event.is_set():
            if not port_open(TOR_CONTROL_PORT):
                self._stop_event.wait(2)
                continue
            cookie = read_cookie()
            if cookie is None:
                self._stop_event.wait(2)
                continue
            try:
                self._monitor_loop(cookie)
            except Exception as e:
                if not self._stop_event.is_set():
                    log(f"BandwidthMonitor reconnexion dans 3s : {e}", "warn")
                    self._stop_event.wait(3)

    def _monitor_loop(self, cookie: bytes):
        cookie_hex = cookie.hex()
        with socket.create_connection(("127.0.0.1", TOR_CONTROL_PORT), timeout=5) as s:
            s.sendall(f"AUTHENTICATE {cookie_hex}\r\nSETEVENTS BANDWIDTH\r\n".encode())
            s.settimeout(5)
            buf = ""
            while not self._stop_event.is_set():
                try:
                    chunk = s.recv(4096).decode("utf-8", errors="replace")
                except socket.timeout:
                    continue
                if not chunk:
                    break
                buf += chunk
                while "\n" in buf:
                    line, buf = buf.split("\n", 1)
                    line = line.strip()
                    # Format : "650 BW <bytes_read> <bytes_written>"
                    if line.startswith("650 BW "):
                        parts = line.split()
                        if len(parts) == 4:
                            try:
                                bw_down = int(parts[2])
                                bw_up   = int(parts[3])
                                with state_lock:
                                    state["bw_down"]       = bw_down
                                    state["bw_up"]         = bw_up
                                    state["bw_total_down"] += bw_down
                                    state["bw_total_up"]   += bw_up
                            except ValueError:
                                pass

bw_monitor = BandwidthMonitor()

# ── AUTO-ROTATION ─────────────────────────────────────────────────────────────

async def _autorotate_loop(interval_sec: int):
    """Envoie NEWNYM toutes les interval_sec secondes tant que Tor est actif."""
    global _last_newnym
    log(f"Auto-rotation activée — nouveau circuit toutes les {interval_sec}s", "ok")
    while True:
        await asyncio.sleep(interval_sec)
        if not port_open(TOR_SOCKS_PORT):
            log("Auto-rotation : Tor non actif — pause", "warn")
            continue
        log("Auto-rotation : nouveau circuit...", "info")
        loop = asyncio.get_event_loop()
        success = await loop.run_in_executor(None, tor_newnym)
        if success:
            _last_newnym = time.time()
            await asyncio.sleep(5)
            loop.run_in_executor(None, _fetch_tor_ip_safe)

@app.post("/autorotate/start")
async def autorotate_start(interval: int = 300):
    """
    Active l'auto-rotation des circuits.
    interval : secondes entre chaque NEWNYM (min 30, max 3600)
    """
    global _autorotate_task, _autorotate_interval
    interval = max(30, min(3600, interval))

    if _autorotate_task and not _autorotate_task.done():
        _autorotate_task.cancel()

    _autorotate_interval = interval
    _autorotate_task = asyncio.get_event_loop().create_task(
        _autorotate_loop(interval)
    )
    return {"ok": True, "interval": interval,
            "msg": f"Auto-rotation activée — circuit toutes les {interval}s"}

@app.post("/autorotate/stop")
async def autorotate_stop():
    global _autorotate_task, _autorotate_interval
    if _autorotate_task and not _autorotate_task.done():
        _autorotate_task.cancel()
    _autorotate_task = None
    _autorotate_interval = 0
    log("Auto-rotation désactivée", "warn")
    return {"ok": True}

@app.get("/autorotate/status")
def autorotate_status():
    active = bool(_autorotate_task and not _autorotate_task.done())
    remaining = 0
    if active and _last_newnym > 0:
        elapsed  = time.time() - _last_newnym
        remaining = max(0, int(_autorotate_interval - elapsed))
    return {
        "active":   active,
        "interval": _autorotate_interval,
        "remaining": remaining,   # secondes avant le prochain NEWNYM
    }

@app.get("/bandwidth")
def bandwidth():
    with state_lock:
        return {
            "down":       state["bw_down"],
            "up":         state["bw_up"],
            "total_down": state["bw_total_down"],
            "total_up":   state["bw_total_up"],
        }

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
    # Fetch bridges frais au démarrage (en arrière-plan pour ne pas bloquer)
    threading.Thread(target=refresh_bridges, daemon=True, name="bridge-refresh").start()
    uvicorn.run(app, host="127.0.0.1", port=BACKEND_PORT, log_level="warning")