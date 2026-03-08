from __future__ import annotations

import argparse
import fnmatch
import os
import shlex
import subprocess
import sys
import threading
import time
import tomllib
import urllib.request
import webbrowser
from pathlib import Path


ROOT_DIR = Path(__file__).resolve().parents[1]
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 56461

DEFAULT_CLI_ARGS = [
    "examples/scenario_hospitality/input.json",
    "--out",
    "examples/output/hospitality.json",
    "--risk-type",
    "impersonation",
]

REQUIRED_PLACEHOLDERS = [
    "SECRET_KEY=change-me-exposuremapper-secret",
    "PASSWORD_PEPPER=change-me-password-pepper",
    "API_KEY_PEPPER=change-me-api-key-pepper",
    "DEFAULT_ADMIN_PASSWORD=change-me-admin-password",
    "OPENAI_API_KEY=",
]


def _format_cmd(cmd: list[str]) -> str:
    if os.name == "nt":
        return subprocess.list2cmdline(cmd)
    return shlex.join(cmd)


def _run(cmd: list[str], *, cwd: Path | None = None, env: dict[str, str] | None = None) -> int:
    print(f"+ {_format_cmd(cmd)}")
    completed = subprocess.run(cmd, cwd=cwd or ROOT_DIR, env=env)
    return completed.returncode


def _run_capture(cmd: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, cwd=ROOT_DIR, capture_output=True, text=True)


def _venv_python() -> Path:
    if os.name == "nt":
        return ROOT_DIR / ".venv" / "Scripts" / "python.exe"
    return ROOT_DIR / ".venv" / "bin" / "python"


def _is_venv_python(python_exec: str) -> bool:
    try:
        return Path(python_exec).resolve() == _venv_python().resolve()
    except OSError:
        return Path(python_exec) == _venv_python()


def _pip_install_cmd(python_exec: str, *args: str) -> list[str]:
    cmd = [python_exec, "-m", "pip", "install"]
    if not _is_venv_python(python_exec):
        cmd.append("--user")
    cmd.extend(args)
    return cmd


def _python_for_tasks() -> str:
    venv_python = _venv_python()
    if venv_python.exists():
        return str(venv_python)
    return sys.executable


def _ensure_venv() -> int:
    venv_python = _venv_python()
    if venv_python.exists():
        return 0
    return _run([sys.executable, "-m", "venv", ".venv"])


def _has_editable_install_support() -> bool:
    pyproject = ROOT_DIR / "pyproject.toml"
    if not pyproject.exists():
        return False
    try:
        data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError):
        return False
    return "build-system" in data and "project" in data


def _install_setup_dependencies(python_exec: str) -> int:
    if _has_editable_install_support():
        return _run(_pip_install_cmd(python_exec, "-e", ".[dev]"))

    requirements = ROOT_DIR / "requirements.txt"
    if requirements.exists():
        return _run(_pip_install_cmd(python_exec, "-r", "requirements.txt"))

    print("error: no install target found (pyproject.toml or requirements.txt).", file=sys.stderr)
    return 2


def _install_runtime_dependencies(python_exec: str) -> int:
    requirements = ROOT_DIR / "requirements.txt"
    if requirements.exists():
        return _run(_pip_install_cmd(python_exec, "-r", "requirements.txt"))
    return _install_setup_dependencies(python_exec)


def _ensure_pip(python_exec: str) -> int:
    probe = _run_capture([python_exec, "-m", "pip", "--version"])
    if probe.returncode == 0:
        return 0
    print("pip not found for selected interpreter; bootstrapping with ensurepip")
    code = _run([python_exec, "-m", "ensurepip", "--upgrade"])
    if code != 0:
        return code
    if _is_venv_python(python_exec):
        return _run([python_exec, "-m", "pip", "install", "--upgrade", "pip"])
    return 0


def cmd_setup(args: argparse.Namespace) -> int:
    if args.venv:
        code = _ensure_venv()
        if code != 0:
            return code
    python_exec = _python_for_tasks()
    code = _ensure_pip(python_exec)
    if code != 0:
        return code
    return _install_setup_dependencies(python_exec)


def cmd_test(args: argparse.Namespace) -> int:
    passthrough = list(args.pytest_args or [])
    if passthrough and passthrough[0] == "--":
        passthrough = passthrough[1:]
    return _run([_python_for_tasks(), "-m", "pytest", *passthrough])


def cmd_cli(args: argparse.Namespace) -> int:
    passthrough = list(args.cli_args or [])
    if passthrough and passthrough[0] == "--":
        passthrough = passthrough[1:]
    if not passthrough:
        passthrough = list(DEFAULT_CLI_ARGS)
    return _run([_python_for_tasks(), "-m", "operational_leverage_framework.cli.main", *passthrough])


def _open_browser_when_ready(url: str, health_url: str, timeout_seconds: float = 30.0) -> None:
    def _worker() -> None:
        deadline = time.time() + timeout_seconds
        while time.time() < deadline:
            try:
                with urllib.request.urlopen(health_url, timeout=2):
                    webbrowser.open(url)
                    return
            except Exception:
                time.sleep(0.5)
        try:
            webbrowser.open(url)
        except Exception:
            pass

    threading.Thread(target=_worker, daemon=True).start()


def cmd_web(args: argparse.Namespace) -> int:
    if not (ROOT_DIR / "app" / "main.py").exists():
        print("error: app/main.py not found.", file=sys.stderr)
        return 2

    code = _ensure_venv()
    if code != 0:
        print("warning: failed to create .venv; falling back to current Python interpreter.", file=sys.stderr)

    python_exec = _python_for_tasks()
    code = _ensure_pip(python_exec)
    if code != 0 and _is_venv_python(python_exec):
        print("warning: pip bootstrap failed in .venv; falling back to current Python interpreter.", file=sys.stderr)
        python_exec = sys.executable
        code = _ensure_pip(python_exec)
    if code != 0:
        return code

    code = _install_runtime_dependencies(python_exec)
    if code != 0 and _is_venv_python(python_exec):
        print("warning: dependency install failed in .venv; retrying with current Python interpreter.", file=sys.stderr)
        python_exec = sys.executable
        code = _ensure_pip(python_exec)
        if code != 0:
            return code
        code = _install_runtime_dependencies(python_exec)
    if code != 0:
        return code

    env_file = ROOT_DIR / ".env"
    if not env_file.exists():
        print("note: .env not found; using runtime-generated local defaults for secrets and peppers.")

    app_url = f"http://{args.host}:{args.port}"
    health_url = f"{app_url}/healthz"
    if not args.no_browser:
        _open_browser_when_ready(app_url, health_url)

    print(f"starting web app at {app_url}")
    return _run(
        [
            python_exec,
            "-m",
            "uvicorn",
            "app.main:app",
            "--host",
            args.host,
            "--port",
            str(args.port),
            "--reload",
        ],
        env=os.environ.copy(),
    )


def _git_tracked_files() -> tuple[list[str], str | None]:
    result = _run_capture(["git", "ls-files", "-z"])
    if result.returncode != 0:
        message = result.stderr.strip() or result.stdout.strip() or "git ls-files failed"
        return [], message
    raw = result.stdout
    files = [item for item in raw.split("\x00") if item]
    return files, None


def _print_check(name: str, ok: bool, details: list[str]) -> None:
    status = "PASS" if ok else "FAIL"
    print(f"[{status}] {name}")
    for item in details:
        print(f"  - {item}")


def cmd_safety(args: argparse.Namespace) -> int:
    tracked_files, git_error = _git_tracked_files()
    if git_error is not None:
        print(f"[FAIL] git status checks")
        print(f"  - {git_error}")
        print("\nRelease safety check failed.")
        return 1

    failures = 0
    tracked_set = set(tracked_files)

    def _exists(rel: str) -> bool:
        return (ROOT_DIR / rel).exists()

    env_tracked = ".env" in tracked_set and _exists(".env")
    _print_check(".env is not tracked", not env_tracked, [".env is tracked in git"] if env_tracked else [])
    failures += int(env_tracked)

    db_runtime = [
        f
        for f in tracked_files
        if _exists(f) and (f.endswith(".db-journal") or f.endswith(".db-wal") or f.endswith(".db"))
    ]
    _print_check(
        "no tracked database runtime artifacts",
        not db_runtime,
        [f"tracked: {f}" for f in db_runtime[:20]],
    )
    failures += int(bool(db_runtime))

    secret_patterns = ["*.pem", "*.key", "*.p12", "*.pfx", "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519"]
    secret_like = []
    for f in tracked_files:
        if not _exists(f):
            continue
        name = Path(f).name
        low = f.lower()
        if low == ".env" or (low.startswith(".env.") and low != ".env.example"):
            secret_like.append(f)
            continue
        if any(fnmatch.fnmatch(name, pattern) for pattern in secret_patterns):
            secret_like.append(f)
    _print_check("no tracked secret-like files", not secret_like, [f"tracked: {f}" for f in secret_like[:20]])
    failures += int(bool(secret_like))

    allowed_export_files = {"exports/README.md", "exports/.gitkeep"}
    export_runtime = [
        f for f in tracked_files if _exists(f) and f.startswith("exports/") and f not in allowed_export_files
    ]
    _print_check(
        "no tracked exports runtime data",
        not export_runtime,
        [f"tracked: {f}" for f in export_runtime[:20]],
    )
    failures += int(bool(export_runtime))

    max_bytes = int(args.max_mb * 1024 * 1024)
    large_files = []
    for rel in tracked_files:
        path = ROOT_DIR / rel
        if path.exists() and path.is_file():
            try:
                size = path.stat().st_size
            except OSError:
                continue
            if size > max_bytes:
                large_files.append((rel, size))
    _print_check(
        f"no tracked files larger than {args.max_mb} MB",
        not large_files,
        [f"{rel} ({size} bytes)" for rel, size in large_files[:20]],
    )
    failures += int(bool(large_files))

    env_example = ROOT_DIR / ".env.example"
    env_example_ok = env_example.exists()
    env_example_details: list[str] = []
    if not env_example.exists():
        env_example_details.append(".env.example is missing")
    _print_check(".env.example exists", env_example_ok, env_example_details)
    failures += int(not env_example_ok)

    placeholder_failures: list[str] = []
    if env_example.exists():
        env_text = env_example.read_text(encoding="utf-8", errors="replace")
        for token in REQUIRED_PLACEHOLDERS:
            if token not in env_text:
                placeholder_failures.append(f".env.example missing placeholder: {token}")
    readme_path = ROOT_DIR / "README.md"
    if readme_path.exists():
        readme_text = readme_path.read_text(encoding="utf-8", errors="replace")
        for token in REQUIRED_PLACEHOLDERS[:-1]:
            if token not in readme_text:
                placeholder_failures.append(f"README.md missing placeholder reference: {token}")
    _print_check("public placeholders are still present", not placeholder_failures, placeholder_failures)
    failures += int(bool(placeholder_failures))

    if failures:
        print("\nRelease safety check failed.")
        return 1
    print("\nRelease safety check passed.")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Cross-platform task runner for Trust Surface.")
    sub = parser.add_subparsers(dest="command", required=True)

    setup_parser = sub.add_parser("setup", help="Install project dependencies.")
    setup_parser.add_argument("--venv", action="store_true", help="Create .venv if missing before install.")
    setup_parser.set_defaults(func=cmd_setup)

    test_parser = sub.add_parser("test", help="Run pytest.")
    test_parser.add_argument("pytest_args", nargs=argparse.REMAINDER, help="Optional pytest args.")
    test_parser.set_defaults(func=cmd_test)

    cli_parser = sub.add_parser("cli", help="Run the project CLI.")
    cli_parser.add_argument("cli_args", nargs=argparse.REMAINDER, help="Args forwarded to cli.main.")
    cli_parser.set_defaults(func=cmd_cli)

    web_parser = sub.add_parser("web", help="Run FastAPI web app on 127.0.0.1:56461.")
    web_parser.add_argument("--host", default=DEFAULT_HOST, help="Web host (default: 127.0.0.1).")
    web_parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="Web port (default: 56461).")
    web_parser.add_argument("--no-browser", action="store_true", help="Do not auto-open browser.")
    web_parser.set_defaults(func=cmd_web)

    safety_parser = sub.add_parser("safety", help="Run release safety checks.")
    safety_parser.add_argument("--max-mb", type=float, default=5.0, help="Maximum allowed tracked file size in MB.")
    safety_parser.set_defaults(func=cmd_safety)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
