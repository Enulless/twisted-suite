"""Practice-lab manager.

Wraps ``docker compose`` against the compose files under
``docker/labs/<lab>/`` to bring DVWA, Juice Shop, vulnerable
WordPress, and Metasploitable2 up/down on demand. The manager has
zero side effects when docker isn't installed; every operation
returns a typed result that the engine API + CLI surface to the
operator.
"""

from .manager import (
    LAB_CATALOGUE,
    LabError,
    LabResult,
    LabSpec,
    LabState,
    LabStatus,
    docker_available,
    get_lab,
    lab_for_step,
    lab_logs,
    lab_status,
    lab_up,
    list_labs,
    take_lab_down,
)

__all__ = [
    "LAB_CATALOGUE",
    "LabError",
    "LabResult",
    "LabSpec",
    "LabState",
    "LabStatus",
    "docker_available",
    "get_lab",
    "lab_for_step",
    "lab_logs",
    "lab_status",
    "lab_up",
    "list_labs",
    "take_lab_down",
]
