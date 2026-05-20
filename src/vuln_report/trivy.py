from __future__ import annotations

import subprocess
from pathlib import Path


def run_trivy_image_scan(image: str, output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    cmd = [
        "docker",
        "run",
        "--rm",
        "-v",
        f"{output_path.parent.resolve()}:/out",
        "aquasec/trivy:latest",
        "image",
        "--quiet",
        "--format",
        "json",
        "--output",
        f"/out/{output_path.name}",
        image,
    ]
    subprocess.run(cmd, check=True)

