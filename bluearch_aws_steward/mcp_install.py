from __future__ import annotations

import json
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Sequence

MCP_SERVER_NAME = "bluearch-aws-steward"
SUPPORTED_MCP_CLIENTS = ("codex", "cursor", "claude")

JSON = Dict[str, Any]
ExecutableFinder = Callable[[str], str | None]


def resolve_mcp_clients(
    requested: Sequence[str],
    *,
    home: Path | None = None,
    executable_finder: ExecutableFinder = shutil.which,
) -> List[str]:
    if not requested:
        raise ValueError("At least one --client is required.")
    unknown = sorted(set(requested) - {*SUPPORTED_MCP_CLIENTS, "all"})
    if unknown:
        raise ValueError(f"Unsupported MCP client(s): {', '.join(unknown)}")
    if "all" in requested and len(set(requested)) > 1:
        raise ValueError("Use --client all by itself, or select clients individually.")
    if "all" not in requested:
        return list(dict.fromkeys(requested))

    home = home or Path.home()
    detected: List[str] = []
    if executable_finder("codex"):
        detected.append("codex")
    if _cursor_is_installed(home, executable_finder):
        detected.append("cursor")
    if executable_finder("claude"):
        detected.append("claude")
    if not detected:
        raise ValueError(
            "No supported MCP client was detected. Select one explicitly with "
            "--client codex, --client cursor, or --client claude."
        )
    return detected


def install_mcp_clients(
    clients: Sequence[str],
    config: JSON,
    *,
    dry_run: bool = False,
    home: Path | None = None,
    executable_finder: ExecutableFinder = shutil.which,
) -> List[JSON]:
    home = home or Path.home()
    server = _server_entry(config)
    results: List[JSON] = []
    for client in clients:
        if client == "cursor":
            results.append(_install_cursor(server, home=home, dry_run=dry_run))
        else:
            results.append(
                _install_native_client(
                    client,
                    server,
                    home=home,
                    dry_run=dry_run,
                    executable_finder=executable_finder,
                )
            )
    return results


def uninstall_mcp_clients(
    clients: Sequence[str],
    *,
    dry_run: bool = False,
    home: Path | None = None,
    executable_finder: ExecutableFinder = shutil.which,
) -> List[JSON]:
    home = home or Path.home()
    results: List[JSON] = []
    for client in clients:
        if client == "cursor":
            results.append(_uninstall_cursor(home=home, dry_run=dry_run))
        else:
            results.append(
                _uninstall_native_client(
                    client,
                    home=home,
                    dry_run=dry_run,
                    executable_finder=executable_finder,
                )
            )
    return results


def native_add_command(client: str, executable: str, server: JSON) -> List[str]:
    environment = server.get("env") or {}
    command = str(server.get("command") or "").strip()
    args = server.get("args") or []
    if not command or not isinstance(args, list) or not isinstance(environment, dict):
        raise ValueError("Steward generated an invalid MCP server entry.")

    if client == "codex":
        result = [executable, "mcp", "add", MCP_SERVER_NAME]
    elif client == "claude":
        result = [executable, "mcp", "add", MCP_SERVER_NAME, "--scope", "user"]
    else:
        raise ValueError(f"Native MCP registration is unsupported for {client}.")

    for key, value in sorted(environment.items()):
        result.extend(["--env", f"{key}={value}"])
    result.extend(["--", command, *(str(value) for value in args)])
    return result


def native_remove_command(client: str, executable: str) -> List[str]:
    if client == "codex":
        return [executable, "mcp", "remove", MCP_SERVER_NAME]
    if client == "claude":
        return [executable, "mcp", "remove", MCP_SERVER_NAME, "--scope", "user"]
    raise ValueError(f"Native MCP registration is unsupported for {client}.")


def _server_entry(config: JSON) -> JSON:
    servers = config.get("mcpServers")
    if not isinstance(servers, dict):
        raise ValueError("Steward generated invalid MCP client configuration.")
    server = servers.get(MCP_SERVER_NAME)
    if not isinstance(server, dict):
        raise ValueError("Steward MCP server entry is missing.")
    return server


def _install_native_client(
    client: str,
    server: JSON,
    *,
    home: Path,
    dry_run: bool,
    executable_finder: ExecutableFinder,
) -> JSON:
    executable_name = "codex" if client == "codex" else "claude"
    executable = executable_finder(executable_name)
    if not executable:
        raise ValueError(f"{client} was not found on PATH. Install it or choose another --client.")
    config_path = _native_config_path(client, home)
    add_command = native_add_command(client, executable, server)
    remove_command = native_remove_command(client, executable)
    result: JSON = {
        "client": client,
        "action": "install",
        "config_path": str(config_path),
        "command": shlex.join(add_command),
        "status": "planned" if dry_run else "installed",
    }
    if dry_run:
        return result

    backup = _backup_file(config_path)
    if backup is not None:
        result["backup_path"] = str(backup)
    existing = client == "claude" or (
        _run_native([executable, "mcp", "get", MCP_SERVER_NAME]).returncode == 0
    )
    if existing:
        removed = _run_native(remove_command)
        if removed.returncode != 0 and client != "claude":
            raise ValueError(_native_failure(client, "remove the existing registration", removed))
    added = _run_native(add_command)
    if added.returncode != 0:
        if backup is not None:
            shutil.copy2(backup, config_path)
        else:
            _run_native(remove_command)
        raise ValueError(_native_failure(client, "install the MCP server", added))
    return result


def _uninstall_native_client(
    client: str,
    *,
    home: Path,
    dry_run: bool,
    executable_finder: ExecutableFinder,
) -> JSON:
    executable_name = "codex" if client == "codex" else "claude"
    executable = executable_finder(executable_name)
    if not executable:
        raise ValueError(f"{client} was not found on PATH. Install it or choose another --client.")
    config_path = _native_config_path(client, home)
    remove_command = native_remove_command(client, executable)
    result: JSON = {
        "client": client,
        "action": "uninstall",
        "config_path": str(config_path),
        "command": shlex.join(remove_command),
        "status": "planned" if dry_run else "removed",
    }
    if dry_run:
        return result

    if client == "codex":
        existing = _run_native([executable, "mcp", "get", MCP_SERVER_NAME])
        if existing.returncode != 0:
            result["status"] = "not-installed"
            return result
    backup = _backup_file(config_path)
    if backup is not None:
        result["backup_path"] = str(backup)
    removed = _run_native(remove_command)
    if removed.returncode != 0:
        if client == "claude":
            result["status"] = "not-installed"
            return result
        raise ValueError(_native_failure(client, "remove the MCP server", removed))
    return result


def _install_cursor(server: JSON, *, home: Path, dry_run: bool) -> JSON:
    config_path = home / ".cursor" / "mcp.json"
    result: JSON = {
        "client": "cursor",
        "action": "install",
        "config_path": str(config_path),
        "status": "planned" if dry_run else "installed",
    }
    if dry_run:
        return result

    payload = _read_json_config(config_path)
    servers = payload.setdefault("mcpServers", {})
    if not isinstance(servers, dict):
        raise ValueError(f"Invalid mcpServers object in {config_path}.")
    backup = _backup_file(config_path)
    if backup is not None:
        result["backup_path"] = str(backup)
    servers[MCP_SERVER_NAME] = server
    _atomic_write_json(config_path, payload)
    return result


def _uninstall_cursor(*, home: Path, dry_run: bool) -> JSON:
    config_path = home / ".cursor" / "mcp.json"
    result: JSON = {
        "client": "cursor",
        "action": "uninstall",
        "config_path": str(config_path),
        "status": "planned" if dry_run else "removed",
    }
    if dry_run:
        return result
    if not config_path.is_file():
        result["status"] = "not-installed"
        return result

    payload = _read_json_config(config_path)
    servers = payload.get("mcpServers")
    if not isinstance(servers, dict) or MCP_SERVER_NAME not in servers:
        result["status"] = "not-installed"
        return result
    backup = _backup_file(config_path)
    if backup is not None:
        result["backup_path"] = str(backup)
    del servers[MCP_SERVER_NAME]
    _atomic_write_json(config_path, payload)
    return result


def _native_config_path(client: str, home: Path) -> Path:
    if client == "codex":
        codex_home = Path(os.environ.get("CODEX_HOME", home / ".codex"))
        return codex_home / "config.toml"
    if client == "claude":
        return home / ".claude.json"
    raise ValueError(f"Unsupported native MCP client: {client}")


def _cursor_is_installed(home: Path, executable_finder: ExecutableFinder) -> bool:
    if executable_finder("cursor") or (home / ".cursor").exists():
        return True
    return sys.platform == "darwin" and Path("/Applications/Cursor.app").exists()


def _read_json_config(path: Path) -> JSON:
    if not path.exists():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"Cannot read valid JSON from {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise ValueError(f"Expected a JSON object in {path}.")
    return payload


def _atomic_write_json(path: Path, payload: JSON) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    existing_mode = path.stat().st_mode & 0o777 if path.exists() else 0o600
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", dir=path.parent, prefix=f".{path.name}.", delete=False
    ) as handle:
        temporary_path = Path(handle.name)
        json.dump(payload, handle, indent=2, sort_keys=True)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    temporary_path.chmod(existing_mode)
    os.replace(temporary_path, path)


def _backup_file(path: Path) -> Path | None:
    if not path.is_file():
        return None
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    backup = path.with_name(f"{path.name}.bluearch-backup-{timestamp}")
    suffix = 1
    while backup.exists():
        backup = path.with_name(f"{path.name}.bluearch-backup-{timestamp}-{suffix}")
        suffix += 1
    shutil.copy2(path, backup)
    return backup


def _run_native(command: Sequence[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        list(command),
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )


def _native_failure(client: str, action: str, completed: subprocess.CompletedProcess[str]) -> str:
    detail = (completed.stderr or completed.stdout or "unknown error").strip()
    return f"Could not {action} for {client}: {detail}"
