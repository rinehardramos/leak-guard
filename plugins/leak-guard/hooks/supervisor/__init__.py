"""OS-specific process supervisor adapters for leak-guard proxy."""
from __future__ import annotations

import sys

from .base import Supervisor


def get_adapter() -> Supervisor:
    """Return the supervisor adapter for the current platform."""
    if sys.platform == "darwin":
        from .launchd import LaunchdSupervisor
        return LaunchdSupervisor()
    if sys.platform.startswith("linux"):
        from .systemd import SystemdSupervisor
        return SystemdSupervisor()
    raise NotImplementedError(f"No supervisor adapter for {sys.platform}")
