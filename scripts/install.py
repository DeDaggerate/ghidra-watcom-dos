#!/usr/bin/env python3

# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Emily "TTG" Banerjee <prs.ttg+dedagger@pm.me>

import argparse
import os
import re
import shutil
import sys
import time
import zipfile
from pathlib import Path

from lib.ghidra import get_ghidra_directory

PROJECT_ROOT = Path(__file__).resolve().parent.parent
NAME = "ghidra-watcom-dos"

CSPEC_FILES = ("x86watcom.cspec", "x86watcom16.cspec", "x86watcom16far.cspec")
COMPILER_ENTRIES = (
		("x86:LE:32:default", '<compiler name="Watcom" spec="x86watcom.cspec" id="watcom"/>'),
		("x86:LE:16:Real Mode", '<compiler name="watcom" spec="x86watcom16.cspec" id="watcom16"/>'),
		("x86:LE:16:Real Mode", '<compiler name="watcom (far)" spec="x86watcom16far.cspec" id="watcom16far"/>'))

def collect_extension() -> Path:
	zip_path = PROJECT_ROOT / "dist" / f"{NAME}.zip"
	if not zip_path.is_file():
		sys.exit(f"error: {zip_path} not found; run `gradle buildExtension` first")

	return zip_path

def install_extension(ghidra_directory: Path, zip_path: Path) -> Path:
	extension_root = ghidra_directory / "Ghidra" / "Extensions"
	if not extension_root.is_dir():
		sys.exit(f"error: {extension_root} not found")

	target = extension_root / NAME
	if target.exists():
		shutil.rmtree(target)

	print(f"[extract] {zip_path.name} -> {extension_root}")

	with zipfile.ZipFile(zip_path) as zf:
		zf.extractall(extension_root)

	# Ghidra's PackedDatabaseCache (used for .gdt / .fidb archives) keys on file
	# mtime to decide whether the cached unpacked copy is stale. Zip extraction
	# preserves the timestamp stored in the archive (typically the 1980 epoch
	# from buildExtension), so re-installing leaves the cache thinking nothing
	# changed and Ghidra serves the OLD type/fingerprint contents. Touch the
	# whole extension tree so the cache invalidates on next read.
	now = time.time()
	for root, _, files in os.walk(target):
		for filename in files:
			os.utime(os.path.join(root, filename), (now, now))

	return target

def patch_cspecs(ghidra_directory: Path) -> None:
	x86_specifications = ghidra_directory / "Ghidra" / "Processors" / "x86" / "data" / "languages"

	ldefs = x86_specifications / "x86.ldefs"
	if not ldefs.is_file():
		sys.exit(f"error: {ldefs} not found")

	print(f"[cspecs] copying into {x86_specifications}")
	for name in CSPEC_FILES:
		shutil.copyfile(PROJECT_ROOT / "data" / "languages" / name, x86_specifications / name)

	print(f"[cspecs] patching {ldefs.name}")

	text = ldefs.read_text(encoding="utf-8")
	for language_id, entry in COMPILER_ENTRIES:
		pattern = re.compile(rf'(<language\b[^>]*\bid="{re.escape(language_id)}"[^>]*>)(.*?)(</language>)', re.DOTALL)

		matches = pattern.search(text)
		if not matches:
			sys.exit(f'error: <language id="{language_id}"> not found in {ldefs.name}')

		body = re.sub(rf'\n[ \t]*{re.escape(entry)}', '', matches.group(2))

		insertion = re.search(r'\n[ \t]*<external_name\b', body)
		if insertion:
			position = insertion.start()
			new_body = body[:position] + "\n    " + entry + body[position:]
		else:
			new_body = body.rstrip() + "\n    " + entry + "\n  "

		text = text[:matches.start(2)] + new_body + text[matches.end(2):]

	ldefs.write_text(text, encoding="utf-8")

parser = argparse.ArgumentParser(description="Install ghidra-watcom-dos extension and/or Watcom compiler specs")
parser.add_argument("--cspecs-only", action="store_true", help="install only the .cspec files and ldefs entries (no built extension zip required)")
arguments = parser.parse_args()

ghidra_directory = get_ghidra_directory()
if not arguments.cspecs_only:
	install_extension(ghidra_directory, collect_extension())

patch_cspecs(ghidra_directory)
print("Done. Restart Ghidra to pick up the changes.")
