#!/usr/bin/env python3

# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Emily "TTG" Banerjee <prs.ttg+dedagger@pm.me>

import argparse
import concurrent.futures
import os
import re
import shutil
import subprocess
import sys
import threading
import time
import urllib.request
import zipfile
from pathlib import Path

from lib.ghidra import get_ghidra_directory

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = PROJECT_ROOT / "ghidra_scripts"
FIDB_DIR = PROJECT_ROOT / "data" / "fidb"
GDT_DIR = PROJECT_ROOT / "data" / "typeinfo"

RELEASE_BASE = "https://github.com/open-watcom/open-watcom-1.9/releases/download/w11.0c-zips"
HEADER_ZIP = "clib_hdr.zip"
PROJECT_NAME = "watcom-fid-scratch"
LIBRARY_NAME = "Watcom"
LIBRARY_VERSION = "11.0c"

DOS_HEADERS = [
	"conio.h",
	"ctype.h",
	"direct.h",
	"dos.h",
	"errno.h",
	"fcntl.h",
	"float.h",
	"graph.h",
	"io.h",
	"limits.h",
	"malloc.h",
	"math.h",
	"process.h",
	"search.h",
	"setjmp.h",
	"share.h",
	"signal.h",
	"stdarg.h",
	"stddef.h",
	"stdio.h",
	"stdlib.h",
	"string.h",
	"sys/locking.h",
	"sys/stat.h",
	"sys/timeb.h",
	"sys/types.h",
	"sys/utime.h",
	"time.h"
]

WATCOM_STRIPS = [
	"__near=",
	"__far=",
	"__huge=",
	"__cdecl=",
	"__pascal=",
	"__stdcall=",
	"__fortran=",
	"__interrupt=",
	"__export=",
	"__loadds=",
	"__saveregs=",
	"__segment=unsigned",
	"_ENABLE_AUTODEPEND",
	"__WATCOMC__=1100"
]

PREFIX_HEADER_NAME = "_watcom_prefix.h"
PREFIX_HEADER_BODY = """ \
#define __based(x)
#define __segname(x)
#define __declspec(x)
"""

GDT_TARGETS = [
	(
		"small",
		[ "__I86__", "__DOS__", "_M_I86", "__SMALL__", "M_I86SM", "_M_IX86=0" ],
		"x86:LE:16:Real Mode",
		"watcom16",
		"watcom16-small.gdt"
	),
	(
		"medium",
		[ "__I86__", "__DOS__", "_M_I86", "__MEDIUM__", "M_I86MM", "_M_IX86=1" ],
		"x86:LE:16:Real Mode",
		"watcom16",
		"watcom16-medium.gdt"
	),
	(
		"compact",
		[ "__I86__", "__DOS__", "_M_I86", "__COMPACT__", "M_I86CM", "_M_IX86=2" ],
		"x86:LE:16:Real Mode",
		"watcom16far",
		"watcom16-compact.gdt"
	),
	(
		"large",
		[ "__I86__", "__DOS__", "_M_I86", "__LARGE__", "M_I86LM", "_M_IX86=3" ],
		"x86:LE:16:Real Mode",
		"watcom16far",
		"watcom16-large.gdt"
	),
	(
		"huge",
		[ "__I86__", "__DOS__", "_M_I86", "__HUGE__", "M_I86HM", "_M_IX86=4" ],
		"x86:LE:16:Real Mode",
		"watcom16far",
		"watcom16-huge.gdt"
	),
	(
		"flat",
		[ "__386__", "__DOS__", "__FLAT__", "_M_IX86=386" ],
		"x86:LE:32:default",
		"watcom",
		"watcom32-flat.gdt"
	)
]

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

def parse_arguments() -> argparse.Namespace:
	parser = argparse.ArgumentParser(description="Build Watcom FID + GDT data archives")
	parser.add_argument("--skip-fid", action="store_true", help="don't rebuild .fidbf files")
	parser.add_argument("--skip-gdt", action="store_true", help="don't rebuild .gdt files")

	return parser.parse_args()

def fetch_zip(name: str) -> Path:
	zip_path = SCRATCH / name
	if zip_path.is_file():
		return zip_path

	url = f"{RELEASE_BASE}/{name}"
	print(f"[download] {url}")
	urllib.request.urlretrieve(url, zip_path)

	return zip_path

def resolve_library_directory(architecture: str, override: str | None) -> Path:
	if override:
		path = Path(override)
		if not path.is_dir():
			sys.exit(f"error: {path} (override for {architecture}) is not a directory")

		return path

	out_directory = SCRATCH / f"clib_{architecture}"
	if not out_directory.is_dir():
		zip_path = fetch_zip(f"clib_{architecture}.zip")
		out_directory.mkdir(parents=True, exist_ok=True)

		print(f"[extract] {zip_path.name}")
		with zipfile.ZipFile(zip_path) as zip_stream:
			zip_stream.extractall(out_directory)

	dos = next((path for path in out_directory.rglob("dos") if path.is_dir()), None)
	if dos is None:
		sys.exit(f"error: no 'dos' subdir under {out_directory}")

	return dos

def resolve_header_directory(override: str | None) -> Path:
	if override:
		path = Path(override)
		if not path.is_dir():
			sys.exit(f"error: {path} (header override) is not a directory")

		raw = path
	else:
		out_directory = SCRATCH / "clib_hdr"
		if not out_directory.is_dir():
			zip_path = fetch_zip(HEADER_ZIP)
			out_directory.mkdir(parents=True, exist_ok=True)

			print(f"[extract] {zip_path.name}")
			with zipfile.ZipFile(zip_path) as zip_stream:
				zip_stream.extractall(out_directory)

		raw = next((path for path in out_directory.rglob("h") if path.is_dir() and (path / "stdio.h").is_file()), None)
		if raw is None:
			sys.exit(f"error: no 'h/' subdir with stdio.h under {out_directory}")

	return sanitize_headers(raw)

def sanitize_headers(raw: Path) -> Path:
	sanitized = SCRATCH / "clib_hdr_sanitized"
	if sanitized.is_dir():
		shutil.rmtree(sanitized)

	print(f"[sanitize] {raw} -> {sanitized}")
	sanitized.mkdir(parents=True, exist_ok=True)
	(sanitized / PREFIX_HEADER_NAME).write_text(PREFIX_HEADER_BODY, encoding="utf-8")

	for src in raw.rglob("*"):
		if not src.is_file(): continue

		relative = src.relative_to(raw)
		destination = sanitized / relative
		destination.parent.mkdir(parents=True, exist_ok=True)

		if src.suffix.lower() not in (".h", ".hpp"):
			shutil.copyfile(src, destination)
			continue

		out_lines = []
		skip_continuation = False
		for line in src.read_text(encoding="utf-8", errors="replace").splitlines(keepends=True):
			stripped = line.lstrip()
			if skip_continuation:
				ends_continuation = not line.rstrip("\n").endswith("\\")
				out_lines.append("\n")
				if ends_continuation: skip_continuation = False
				continue

			if stripped.startswith("#pragma"):
				out_lines.append("\n")
				if line.rstrip("\n").endswith("\\"): skip_continuation = True
				continue

			out_lines.append(line)

		destination.write_text("".join(out_lines), encoding="utf-8")

	return sanitized

HEARTBEAT_INTERVAL = 30

NOISE_PATTERN = re.compile(
		r"^("
		r"openjdk version|"
		r"OpenJDK Runtime Environment|"
		r"OpenJDK \d+-Bit Server VM|"
		r"WARNING: Final field|"
		r"WARNING: Use --enable-final-field-mutation|"
		r"WARNING: Mutating final fields|"
		r"WARNING: A terminally deprecated method|"
		r"WARNING: sun\.misc\.Unsafe|"
		r"WARNING: Please consider reporting"
		r")")

def tail_log_line(path: Path) -> str:
	try:
		with path.open("rb") as stream:
			stream.seek(0, os.SEEK_END)
			size = stream.tell()
			stream.seek(max(0, size - 8192))
			tail = stream.read().decode("utf-8", errors="replace")
	except FileNotFoundError:
		return ""

	for line in reversed(tail.splitlines()):
		stripped = line.strip()
		if stripped: return stripped

	return ""

def headless(project_target: str, *script_args: str, log: str, tag: str) -> None:
	log_path = SCRATCH / log
	log_path.write_text("", encoding="utf-8")

	stop = threading.Event()
	start = time.monotonic()

	def heartbeat() -> None:
		while not stop.wait(HEARTBEAT_INTERVAL):
			elapsed = int(time.monotonic() - start)
			last = tail_log_line(log_path)
			if len(last) > 110: last = last[:107] + "..."
			suffix = f": {last}" if last else ""
			print(f"[{tag}] still running ({elapsed}s){suffix}")

	command = [ str(ANALYZE), str(PROJECT_DIRECTORY), project_target, *script_args, "-log", str(log_path) ]
	process = subprocess.Popen(
			command,
			stdout=subprocess.DEVNULL,
			stderr=subprocess.PIPE,
			text=True,
			bufsize=1)

	def drain_stderr() -> None:
		for line in process.stderr:
			if NOISE_PATTERN.match(line): continue
			sys.stderr.write(f"[{tag}] {line}")

	stderr_thread = threading.Thread(target=drain_stderr, daemon=True)
	stderr_thread.start()

	heartbeat_thread = threading.Thread(target=heartbeat, daemon=True)
	heartbeat_thread.start()

	try:
		returncode = process.wait()
		if returncode != 0:
			raise subprocess.CalledProcessError(returncode, command)
	finally:
		stop.set()
		heartbeat_thread.join(timeout=1)
		stderr_thread.join(timeout=2)

def run_fid_pipeline(pipeline: dict) -> None:
	tag = pipeline["tag"]
	label = f"fid {tag}-bit"
	library_directory = resolve_library_directory(pipeline["arch"], os.environ.get(pipeline["env_override"]))

	fidbf = FIDB_DIR / pipeline["fidbf"]
	fidbf.unlink(missing_ok=True)

	print(f"[{label}] source: {library_directory}")

	script_args: list[str] = [ "-scriptPath", str(SCRIPTS), "-noanalysis" ]

	for filename, folder in pipeline["imports"]:
		path = library_directory / filename
		if not path.is_file():
			print(f"[{label}] skip (missing): {filename}")
			continue

		script_args += [ "-preScript", "ImportOmfLibrary.java", str(path), folder, pipeline["language"], pipeline["cspec"] ]

	variant_args: list[str] = []
	for folder, variant in pipeline["variants"]:
		variant_args += [folder, variant]

	script_args += [ "-preScript", "BuildWatcomFid.java", str(fidbf), LIBRARY_NAME, LIBRARY_VERSION, *variant_args ]

	project_name = f"{PROJECT_NAME}-{tag}"
	print(f"[{label}] running headless")

	start = time.monotonic()
	headless(project_name, *script_args, log=f"build-fid-{tag}.log", tag=label)
	elapsed = int(time.monotonic() - start)
	print(f"[{label}] wrote {fidbf} ({fidbf.stat().st_size} bytes, {elapsed}s)")

def run_gdt_target(target: tuple, header_directory: Path) -> bool:
	variant, defines, language_id, compiler_id, gdt_name = target
	label = f"gdt {variant}"

	gdt_path = GDT_DIR / gdt_name
	gdt_path.unlink(missing_ok=True)
	dump_path = GDT_DIR / f"{gdt_name}_CParser.out"
	dump_path.unlink(missing_ok=True)

	print(f"[{label}] parsing into {gdt_path.name}")

	project_name = f"{PROJECT_NAME}-gdt-{variant}"
	script_args = [
		"-scriptPath", str(SCRIPTS),
		"-noanalysis",
		"-preScript", "ParseHeadersToGdt.java",
		str(gdt_path),
		str(header_directory),
		language_id,
		compiler_id,
		";".join(defines + WATCOM_STRIPS),
		";".join([PREFIX_HEADER_NAME] + DOS_HEADERS),
	]

	start = time.monotonic()
	try:
		headless(project_name, *script_args, log=f"build-gdt-{variant}.log", tag=label)
	except subprocess.CalledProcessError as exception:
		print(f"[{label}] FAILED (see scratch/build-gdt-{variant}.log): {exception}")
		return False
	finally:
		dump_path.unlink(missing_ok=True)

	if not gdt_path.is_file():
		print(f"[{label}] FAILED (no output produced; see scratch/build-gdt-{variant}.log)")
		return False

	elapsed = int(time.monotonic() - start)
	print(f"[{label}] wrote {gdt_path} ({gdt_path.stat().st_size} bytes, {elapsed}s)")
	return True

arguments = parse_arguments()

ghidra_directory = get_ghidra_directory()

ANALYZE = None
for name in ("analyzeHeadless", "analyzeHeadless.bat"):
	candidate = ghidra_directory / "support" / name
	if candidate.is_file():
		ANALYZE = candidate
		break

if ANALYZE is None:
	sys.exit(f"error: analyzeHeadless not found under {ghidra_directory / 'support'}")

SCRATCH = PROJECT_ROOT / "scratch"
SCRATCH.mkdir(parents=True, exist_ok=True)
FIDB_DIR.mkdir(parents=True, exist_ok=True)
GDT_DIR.mkdir(parents=True, exist_ok=True)

PROJECT_DIRECTORY = SCRATCH / "ghidra"
PROJECT_DIRECTORY.mkdir(parents=True, exist_ok=True)

project_prefixes = [f"{PROJECT_NAME}-{pipeline['tag']}" for pipeline in PIPELINES]
project_prefixes += [f"{PROJECT_NAME}-gdt-{t[0]}" for t in GDT_TARGETS]
for prefix in project_prefixes:
	for suffix in (".gpr", ".rep"):
		path = PROJECT_DIRECTORY / f"{prefix}{suffix}"
		if path.is_dir():
			shutil.rmtree(path)
		elif path.is_file():
			path.unlink()

print(f"[build-data] scratch={SCRATCH}")

jobs: list = []
if not arguments.skip_fid:
	jobs += [("fid", pipeline) for pipeline in PIPELINES]

if not arguments.skip_gdt:
	header_directory = resolve_header_directory(os.environ.get("WATCOM_HDR"))
	print(f"[gdt] headers: {header_directory}")
	jobs += [("gdt", (target, header_directory)) for target in GDT_TARGETS]

def dispatch(job):
	kind, payload = job
	if kind == "fid":
		run_fid_pipeline(payload)
		return True

	target, header_directory = payload
	return run_gdt_target(target, header_directory)

failures = []
total = len(jobs)
overall_start = time.monotonic()
with concurrent.futures.ThreadPoolExecutor(max_workers=min(total, 4)) as ex:
	futures = {ex.submit(dispatch, job): job for job in jobs}
	for done, f in enumerate(concurrent.futures.as_completed(futures), start=1):
		job = futures[f]
		if f.result() is False:
			failures.append(job)

		elapsed = int(time.monotonic() - overall_start)
		print(f"[build-data] {done}/{total} jobs done ({elapsed}s elapsed)")

print(f"[build-data] cleaning {PROJECT_DIRECTORY}")
shutil.rmtree(PROJECT_DIRECTORY, ignore_errors=True)

if failures:
	print(f"[build-data] done with {len(failures)} failure(s):")
	for kind, payload in failures:
		label = payload["fidbf"] if kind == "fid" else payload[0][4]
		print(f"  - {kind} {label}")

	sys.exit(1)

print("[build-data] done.")
