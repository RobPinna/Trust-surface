from __future__ import annotations

import os
import socket
import tempfile
import threading
import time
import urllib.request
import webbrowser
from pathlib import Path

import uvicorn

from operational_leverage_framework import get_runtime_version

APP_IMPORT_PATH = "app.main:app"
HOST = "127.0.0.1"
PREFERRED_PORT = 56461


def _can_bind_localhost(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind((HOST, int(port)))
            return True
        except OSError:
            return False


def _find_port(preferred_port: int = PREFERRED_PORT, max_attempts: int = 50) -> int:
    if _can_bind_localhost(preferred_port):
        return preferred_port

    for port in range(preferred_port + 1, preferred_port + 1 + max_attempts):
        if _can_bind_localhost(port):
            return int(port)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind((HOST, 0))
        return int(sock.getsockname()[1])


def _open_browser_when_ready(url: str, health_url: str, timeout_seconds: float = 30.0) -> None:
    def _worker() -> None:
        deadline = time.time() + timeout_seconds
        while time.time() < deadline:
            try:
                with urllib.request.urlopen(health_url, timeout=2):
                    webbrowser.open(url)
                    return
            except Exception:
                time.sleep(0.35)
        try:
            webbrowser.open(url)
        except Exception:
            pass

    threading.Thread(target=_worker, daemon=True).start()


def _resolve_runtime_dir() -> Path:
    configured = os.getenv("RUNTIME_DIR", "").strip()
    if configured:
        candidates = [Path(configured).expanduser()]
    else:
        candidates = []

    local_appdata = os.getenv("LOCALAPPDATA", "").strip()
    if local_appdata:
        candidates.append(Path(local_appdata) / "TrustSurface" / "data")
    candidates.append(Path.home() / ".trust_surface" / "data")
    candidates.append(Path(tempfile.gettempdir()) / "TrustSurface" / "data")

    for candidate in candidates:
        try:
            candidate.mkdir(parents=True, exist_ok=True)
            return candidate
        except OSError:
            continue
    raise RuntimeError("Unable to create a writable runtime data directory.")


def _configure_runtime_env() -> Path:
    runtime_dir = _resolve_runtime_dir()
    os.environ.setdefault("RUNTIME_DIR", str(runtime_dir))
    db_path = runtime_dir / "exposuremapper.db"
    os.environ.setdefault("DATABASE_URL", f"sqlite:///{db_path.as_posix()}")
    return runtime_dir


def main() -> int:
    data_dir = _configure_runtime_env()
    from app.main import app as fastapi_app

    port = _find_port(PREFERRED_PORT)
    base_url = f"http://{HOST}:{port}"
    version = get_runtime_version()
    print(f"Version: {version}", flush=True)
    print(f"Web UI: {base_url}/", flush=True)
    print(f"Data dir: {data_dir.resolve()}", flush=True)
    print(f"App import path: {APP_IMPORT_PATH}", flush=True)

    _open_browser_when_ready(base_url + "/", base_url + "/healthz")
    uvicorn.run(
        fastapi_app,
        host=HOST,
        port=port,
        reload=False,
        access_log=False,
        log_level="warning",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
