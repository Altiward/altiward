#!/usr/bin/env python3
"""Verify the exact OCI image and extract final Caddy binaries without executing it."""
import hashlib
import io
import json
from pathlib import Path
import sys
import tarfile

root = Path(__file__).resolve().parent.parent
out = Path(sys.argv[1])
reference = (root / "deploy/caddy/image.txt").read_text().strip()
expected = reference.rsplit("@", 1)[1]
actual = json.loads((out / "metadata.json").read_text())["containerimage.digest"]
if actual != expected:
    sys.exit(f"Caddy digest {actual}, expected {expected}. Review and update all deployment pins after changing the build.")
if f"image: {reference}" not in (root / "deploy/compose/compose.yaml").read_text():
    sys.exit("Compose does not use the pinned Caddy image")
if f"var caddyImage = '{reference}'" not in (root / "deploy/azure/main.bicep").read_text():
    sys.exit("Azure does not use the pinned Caddy image")

with tarfile.open(out / "caddy.oci.tar") as archive:
    def blob(digest):
        algorithm, value = digest.split(":", 1)
        if algorithm != "sha256" or len(value) != 64:
            raise ValueError("unexpected OCI digest")
        data = archive.extractfile(f"blobs/sha256/{value}").read()
        if hashlib.sha256(data).hexdigest() != value:
            raise ValueError("OCI blob digest mismatch")
        return data

    index = json.loads(blob(expected))
    platforms = set()
    for descriptor in index["manifests"]:
        platform = descriptor["platform"]
        arch = platform["architecture"]
        if platform["os"] != "linux" or arch not in ("amd64", "arm64") or arch in platforms:
            raise ValueError("unexpected Caddy platform")
        platforms.add(arch)
        manifest = json.loads(blob(descriptor["digest"]))
        blob(manifest["config"]["digest"])
        binary = None
        for layer in manifest["layers"]:
            with tarfile.open(fileobj=io.BytesIO(blob(layer["digest"]))) as files:
                for member in files:
                    if member.name.lstrip("./") == "usr/bin/caddy":
                        if not member.isfile():
                            raise ValueError("Caddy binary is not a regular file")
                        binary = files.extractfile(member).read()
        if binary is None:
            raise ValueError("Caddy binary absent")
        (out / f"caddy-{arch}").write_bytes(binary)
    if platforms != {"amd64", "arm64"}:
        raise ValueError("Caddy must support amd64 and arm64")
print(f"Verified {reference}; extracted both final binaries for scanning.")
