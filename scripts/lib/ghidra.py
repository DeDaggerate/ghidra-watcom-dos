import os
import sys
from pathlib import Path

def get_ghidra_directory():
    path = os.environ.get("GHIDRA_INSTALL_DIR")
    if(path is None):
        sys.exit(f"error: $GHIDRA_INSTALL_DIR not set")

    directory = Path(path)
    if not (directory / "Ghidra").is_dir():
        sys.exit(f"error: {directory} doesn't look like a Ghidra install")

    return directory
