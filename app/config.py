import json
import os
import secrets
import sys
import tempfile
from functools import lru_cache
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent


def _load_env_file_if_present() -> None:
    env_file = BASE_DIR / ".env"
    if not env_file.exists():
        return
    try:
        lines = env_file.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return

    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        if not key or key in os.environ:
            continue
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            value = value[1:-1]
        os.environ[key] = value


_load_env_file_if_present()


_RUNTIME_SECRET_PLACEHOLDERS = {
    "SECRET_KEY": "change-me-exposuremapper-secret",
    "PASSWORD_PEPPER": "change-me-password-pepper",
    "API_KEY_PEPPER": "change-me-api-key-pepper",
}
_RUNTIME_GENERATED_VALUES: dict[str, str] = {}
_RUNTIME_SECRETS_FILENAME = ".runtime_secrets.json"


def _default_runtime_dir() -> Path:
    if getattr(sys, "frozen", False) or getattr(sys, "_MEIPASS", ""):
        candidates: list[Path] = []
        local_appdata = os.getenv("LOCALAPPDATA", "").strip()
        if local_appdata:
            candidates.append(Path(local_appdata) / "TrustSurface" / "data")
        candidates.append(Path.home() / ".trust_surface" / "data")
        candidates.append(Path.cwd() / "data")
        candidates.append(Path(tempfile.gettempdir()) / "TrustSurface" / "data")

        for path in candidates:
            try:
                path.mkdir(parents=True, exist_ok=True)
                return path
            except OSError:
                continue
    return BASE_DIR / "data"


def _runtime_secrets_store_path() -> Path:
    configured = os.getenv("RUNTIME_DIR", "").strip()
    root = Path(configured).expanduser() if configured else _default_runtime_dir()
    return root / _RUNTIME_SECRETS_FILENAME


def _load_runtime_secrets_store() -> dict[str, str]:
    path = _runtime_secrets_store_path()
    if not path.exists():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    if not isinstance(payload, dict):
        return {}
    return {str(k): str(v) for k, v in payload.items() if isinstance(k, str) and isinstance(v, str)}


def _save_runtime_secrets_store(values: dict[str, str]) -> None:
    path = _runtime_secrets_store_path()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_text(json.dumps(values, indent=2, sort_keys=True), encoding="utf-8")
        os.replace(tmp, path)
    except OSError:
        return


_RUNTIME_PERSISTED_VALUES = _load_runtime_secrets_store()


def _runtime_secret(env_name: str, *, token_size: int = 32) -> str:
    current = os.getenv(env_name, "").strip()
    placeholder = _RUNTIME_SECRET_PLACEHOLDERS.get(env_name, "")
    if current and current != placeholder:
        return current
    if env_name in _RUNTIME_GENERATED_VALUES:
        return _RUNTIME_GENERATED_VALUES[env_name]

    persisted = _RUNTIME_PERSISTED_VALUES.get(env_name, "").strip()
    if persisted:
        _RUNTIME_GENERATED_VALUES[env_name] = persisted
        return persisted

    generated = secrets.token_urlsafe(token_size)
    _RUNTIME_GENERATED_VALUES[env_name] = generated
    _RUNTIME_PERSISTED_VALUES[env_name] = generated
    _save_runtime_secrets_store(_RUNTIME_PERSISTED_VALUES)
    return generated


def _split_csv(raw: str) -> list[str]:
    return [item.strip() for item in (raw or "").split(",") if item.strip()]


class Settings:
    def __init__(self) -> None:
        self.app_name: str = os.getenv("APP_NAME", "ExposureMapper TI")
        self.app_env: str = os.getenv("APP_ENV", "dev")
        self.secret_key: str = _runtime_secret("SECRET_KEY")
        self.password_pepper: str = _runtime_secret("PASSWORD_PEPPER")
        self.api_key_pepper: str = _runtime_secret("API_KEY_PEPPER")
        self.session_cookie_name: str = os.getenv("SESSION_COOKIE_NAME", "exposuremapper_session")
        self.runtime_dir: Path = Path(os.getenv("RUNTIME_DIR", str(_default_runtime_dir()))).expanduser()
        self.runtime_dir.mkdir(parents=True, exist_ok=True)
        default_db_path: Path = self.runtime_dir / "exposuremapper.db"
        self.database_url: str = os.getenv("DATABASE_URL", f"sqlite:///{default_db_path.as_posix()}")
        self.request_timeout_seconds: int = int(os.getenv("REQUEST_TIMEOUT_SECONDS", "8"))
        self.website_user_agent: str = os.getenv("WEBSITE_USER_AGENT", "ExposureMapperTI/1.0 (+local-assessment)")
        self.default_admin_user: str = os.getenv("DEFAULT_ADMIN_USER", "admin")
        self.default_admin_password: str = os.getenv("DEFAULT_ADMIN_PASSWORD", "admin123!")
        self.llm_provider: str = os.getenv("LLM_PROVIDER", "openai")
        self.openai_api_key: str = os.getenv("OPENAI_API_KEY", "")
        self.openai_reasoner_model: str = os.getenv("OPENAI_REASONER_MODEL", "gpt-4.1")
        self.anthropic_api_key: str = os.getenv("ANTHROPIC_API_KEY", "")
        self.anthropic_reasoner_model: str = os.getenv("ANTHROPIC_REASONER_MODEL", "claude-sonnet-4-6")
        self.openai_hypothesis_confidence_threshold: int = int(
            os.getenv("OPENAI_HYPOTHESIS_CONFIDENCE_THRESHOLD", "55")
        )
        self.cors_allowed_origins: list[str] = _split_csv(
            os.getenv(
                "CORS_ALLOWED_ORIGINS",
                "http://127.0.0.1,http://localhost,http://127.0.0.1:56461,http://localhost:56461",
            )
        )
        self.cors_allow_origin_regex: str = os.getenv(
            "CORS_ALLOW_ORIGIN_REGEX",
            r"^https?://(localhost|127\.0\.0\.1)(:\d+)?$",
        )
        # Admin-only debug toggles (UI may display additional validator details).
        self.admin_debug_risk: bool = os.getenv("ADMIN_DEBUG_RISK", "0").strip() == "1"


@lru_cache
def get_settings() -> Settings:
    return Settings()
