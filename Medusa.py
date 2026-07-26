#!/usr/bin/env python3

from dataclasses import dataclass, field
from uuid import uuid4
import os
import json
from pathlib import Path

FORKS = 66440
MAPS = 9
STABILIZERS = 2

BASE_DEFINITIONS = [
    "state",
    "origin",
    "path",
    "dependency",
    "integrity",
    "transition",
    "behavior",
]

REPORT_DIR = Path.home() / "shovel_reports" / "medusa"
REPORT_DIR.mkdir(parents=True, exist_ok=True)


def socket_value(origin_factor=1.0, locality_factor=1.0):
    value = (
        (5.2 / 4.3 / 3.104 / 1.0 / 0.0102)
        * origin_factor
        * locality_factor
        + 0.0203049
    )
    return value, value - 1.0


@dataclass
class MedusaFork:
    fork_id: int
    pid: int
    maps: int = MAPS
    definitions: list = field(default_factory=lambda: BASE_DEFINITIONS.copy())
    stabilizers: list = field(default_factory=lambda: [
        "variance_control",
        "baseline_lock",
    ])
    uuid: str = field(default_factory=lambda: str(uuid4()))
    socket: float = 0.0
    error: float = 0.0

    def compute_socket(self, origin=1.0, locality=1.0):
        self.socket, self.error = socket_value(origin, locality)

    def telemetry(self):
        return {
            "fork": self.fork_id,
            "pid": self.pid,
            "uuid": self.uuid,
            "maps": self.maps,
            "definitions": len(self.definitions),
            "stabilizers": len(self.stabilizers),
            "socket": round(self.socket, 6),
            "error": round(self.error, 6),
            "state": "observed",
        }


def main():
    pid = os.getpid()

    report = REPORT_DIR / "telemetry.jsonl"

    with report.open("w") as f:
        for i in range(FORKS):
            node = MedusaFork(i, pid)
            node.compute_socket()

            f.write(json.dumps(node.telemetry()) + "\n")

    print(f"Wrote {FORKS} telemetry records to {report}")


if __name__ == "__main__":
    main()