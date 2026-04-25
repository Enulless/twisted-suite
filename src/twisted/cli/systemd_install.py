"""Install a systemd user service for the engine."""

from __future__ import annotations

import contextlib
import os
import shutil
import sys
from pathlib import Path

from ..core.settings import Settings

UNIT_TEMPLATE = """\
[Unit]
Description=Twisted Pen Testing Suite — engine
After=network.target

[Service]
Type=simple
ExecStart={twisted_bin} serve --host {host} --port {port}
Restart=on-failure
RestartSec=5
Environment=TWISTED_DATA_ROOT={data_root}
{archive_env}
Environment=TWISTED_TOKEN_FILE={token_file}

[Install]
WantedBy=default.target
"""


def install_user_unit(settings: Settings, *, name: str = "twisted-engine.service") -> Path:
    user_units = Path.home() / ".config" / "systemd" / "user"
    user_units.mkdir(parents=True, exist_ok=True)
    twisted_bin = shutil.which("twisted") or f"{sys.executable} -m twisted.cli"
    archive_env = (f"Environment=TWISTED_ARCHIVE_ROOT={settings.archive_root}"
                   if settings.archive_root else "")
    body = UNIT_TEMPLATE.format(
        twisted_bin=twisted_bin,
        host=settings.engine_host,
        port=settings.engine_port,
        data_root=settings.data_root,
        archive_env=archive_env,
        token_file=settings.token_file,
    )
    target = user_units / name
    target.write_text(body)
    with contextlib.suppress(OSError):
        os.chmod(target, 0o644)
    return target
