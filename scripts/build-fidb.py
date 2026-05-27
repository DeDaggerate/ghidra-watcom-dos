#!/usr/bin/env python3

# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Emily "TTG" Banerjee <prs.ttg+dedagger@pm.me>

import argparse
import concurrent.futures
import os
import shutil
import subprocess
import sys
import urllib.request
import zipfile
from pathlib import Path

from lib.ghidra import get_ghidra_directory

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = PROJECT_ROOT / "ghidra_scripts"
FIDB_DIR = PROJECT_ROOT / "data" / "fidb"

RELEASE_BASE = "https://github.com/open-watcom/open-watcom-1.9/releases/download/w11.0c-zips"
PROJECT_NAME = "watcom-fid-scratch"
LIBRARY_NAME = "Watcom"
LIBRARY_VERSION = "11.0c"


PIPELINES = [
	{
		"tag": "16",
		"arch": "d16",
		"env_override": "WATCOM_LIB16",
		"language": "x86:LE:16:Real Mode",
		"cspec": "watcom16",
		"fidbf": "watcom16-libs.fidbf",
		"imports": [
			*((f"clib{m}.lib", f"/16/clib-{m}") for m in ("s", "m", "c", "l", "h", "om", "ol")),
			("emu87.lib", "/16/emu87"),
			("graph.lib", "/16/graph"),
			("cstart_t.obj", "/16/startup"),
			("dos16m.obj", "/16/startup"),
			("binmode.obj", "/16/startup"),
			("commode.obj", "/16/startup"),
		],
		"variants": [
			("/16/clib-s", "Real Mode (small)"),
			("/16/clib-m", "Real Mode (medium)"),
			("/16/clib-c", "Real Mode (compact)"),
			("/16/clib-l", "Real Mode (large)"),
			("/16/clib-h", "Real Mode (huge)"),
			("/16/clib-om", "Real Mode (medium, opt-size)"),
			("/16/clib-ol", "Real Mode (large, opt-size)"),
			("/16/emu87", "FPU emulation"),
			("/16/graph", "Graphics (16-bit)"),
			("/16/startup", "Startup (DOS 16-bit)"),
		],
	},
	{
		"tag": "32",
		"arch": "d32",
		"env_override": "WATCOM_LIB32",
		"language": "x86:LE:32:default",
		"cspec": "watcom",
		"fidbf": "watcom32-libs.fidbf",
		"imports": [
			("clib3r.lib", "/32/clib3-r"),
			("clib3s.lib", "/32/clib3-s"),
			("emu387.lib", "/32/emu387"),
			("graph.lib", "/32/graph"),
			("cstrtx3r.obj", "/32/startup-reg"),
			("adiestrt.obj", "/32/startup-reg"),
			("adifstrt.obj", "/32/startup-reg"),
			("cstrtx3s.obj", "/32/startup-stk"),
			("adsstart.obj", "/32/startup-stk"),
			("binmode.obj", "/32/startup-stk"),
			("commode.obj", "/32/startup-stk"),
		],
		"variants": [
			("/32/clib3-r", "Flat 32 (register call)"),
			("/32/clib3-s", "Flat 32 (stack call)"),
			("/32/emu387", "FPU emulation"),
			("/32/graph", "Graphics (32-bit)"),
			("/32/startup-reg", "Startup (DOS 32-bit register)"),
			("/32/startup-stk", "Startup (DOS 32-bit stack)"),
		],
	},
]


def resolve_library_directory(architecture: str, override: str | None) -> Path:
	if override:
		path = Path(override)
		if not path.is_dir(): sys.exit(f"error: {path} (override for {architecture}) is not a directory")
		return path

	zip_path = SCRATCH / f"clib_{architecture}.zip"
	out_directory = SCRATCH / f"clib_{architecture}"

	if not out_directory.is_dir():
		if not zip_path.is_file():
			url = f"{RELEASE_BASE}/clib_{architecture}.zip"
			print(f"[download] {url}")
			urllib.request.urlretrieve(url, zip_path)

		out_directory.mkdir(parents=True, exist_ok=True)

		print(f"[extract] {zip_path.name}")
		with zipfile.ZipFile(zip_path) as zip_stream:
			zip_stream.extractall(out_directory)

	dos = next((path for path in out_directory.rglob("dos") if path.is_dir()), None)
	if dos is None: sys.exit(f"error: no 'dos' subdir under {out_directory}")

	return dos


def headless(project_target: str, *script_args: str, log: str) -> None:
	subprocess.run(
			[ str(ANALYZE), str(PROJECT_DIRECTORY), project_target, *script_args, "-log", str(SCRATCH / log) ],
			check=True,
			stdout=subprocess.DEVNULL)

def run_pipeline(pipeline: dict) -> None:
	tag = pipeline["tag"]
	library_directory = resolve_library_directory(pipeline["arch"], os.environ.get(pipeline["env_override"]))

	fidbf = FIDB_DIR / pipeline["fidbf"]
	fidbf.unlink(missing_ok=True)

	print(f"[{tag}-bit] source: {library_directory}")

	script_args: list[str] = [ "-scriptPath", str(SCRIPTS), "-noanalysis" ]

	for filename, folder in pipeline["imports"]:
		path = library_directory / filename
		if not path.is_file():
			print(f"[{tag}-bit] skip (missing): {filename}")
			continue

		script_args += [ "-preScript", "ImportOmfLibrary.java", str(path), folder, pipeline["language"], pipeline["cspec"] ]

	variant_args: list[str] = []
	for folder, variant in pipeline["variants"]:
		variant_args += [folder, variant]

	script_args += [ "-preScript", "BuildWatcomFid.java", str(fidbf), LIBRARY_NAME, LIBRARY_VERSION, *variant_args ]

	project_name = f"{PROJECT_NAME}-{tag}"
	print(f"[{tag}-bit] running headless ({(len(script_args) - 3) // 6 - 1} imports + build)")

	headless(project_name, *script_args, log=f"build-{tag}.log")
	print(f"[{tag}-bit] wrote {fidbf} ({fidbf.stat().st_size} bytes)")

ghidra_directory = get_ghidra_directory()

ANALYZE = None
for name in ("analyzeHeadless", "analyzeHeadless.bat"):
	candidate = ghidra_directory / "support" / name
	if candidate.is_file():
		ANALYZE = candidate
		break

if ANALYZE is None:
	sys.exit(f"error: analyzeHeadless not found under {ghidra_directory / 'support'}")

SCRATCH = Path(args.scratch_dir) if args.scratch_dir else (PROJECT_ROOT / "scratch")
SCRATCH.mkdir(parents=True, exist_ok=True)
FIDB_DIR.mkdir(parents=True, exist_ok=True)

PROJECT_DIRECTORY = SCRATCH / "ghidra"
PROJECT_DIRECTORY.mkdir(parents=True, exist_ok=True)
for pipeline in PIPELINES:
	for suffix in (".gpr", ".rep"):
		path = PROJECT_DIRECTORY / f"{PROJECT_NAME}-{pipeline['tag']}{suffix}"
		if path.is_dir():
			shutil.rmtree(path)
		elif path.is_file():
			path.unlink()

print(f"[build-fidb] scratch={SCRATCH}")
if args.serial:
	for pipeline in PIPELINES:
		run_pipeline(pipeline)
else:
	with concurrent.futures.ThreadPoolExecutor(max_workers=len(PIPELINES)) as ex:
		futures = [ex.submit(run_pipeline, p) for p in PIPELINES]
		for f in futures:
			f.result()

if not args.keep_scratch:
	print(f"[build-fidb] cleaning {PROJECT_DIRECTORY}")
	shutil.rmtree(PROJECT_DIRECTORY, ignore_errors=True)
print("[build-fidb] done.")
