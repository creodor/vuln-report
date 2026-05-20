from __future__ import annotations

import subprocess
import shutil
from pathlib import Path

TRIVY_IMAGE = "aquasec/trivy:0.70.0"


def run_trivy_image_scan(image: str, output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    if shutil.which("trivy"):
        subprocess.run(
            [
                "trivy",
                "image",
                "--quiet",
                "--format",
                "json",
                "--output",
                str(output_path),
                image,
            ],
            check=True,
        )
        return

    cmd = [
        "docker",
        "run",
        "--rm",
        "-v",
        f"{output_path.parent.resolve()}:/out",
        TRIVY_IMAGE,
        "image",
        "--quiet",
        "--format",
        "json",
        "--output",
        f"/out/{output_path.name}",
        image,
    ]
    subprocess.run(cmd, check=True)
