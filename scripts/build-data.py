#!/usr/bin/env python3

# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Emily "TTG" Banerjee <prs.ttg+dedagger@pm.me>

import argparse
import concurrent.futures
import fnmatch
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import threading
import time
import urllib.request
import zipfile
from pathlib import Path

import clang.cindex

from lib.ghidra import get_ghidra_directory

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = PROJECT_ROOT / "ghidra_scripts"
FIDB_DIR = PROJECT_ROOT / "data" / "fidb"
GDT_DIR = PROJECT_ROOT / "data" / "typeinfo"
NORETURN_DIR = PROJECT_ROOT / "data" / "noreturn"
CATEGORIES_FILE = PROJECT_ROOT / "data" / "crt_categories.json"

RELEASE_BASE = "https://github.com/open-watcom/open-watcom-1.9/releases/download/w11.0c-zips"
HEADER_ZIP = "clib_hdr.zip"
PROJECT_NAME = "watcom-fid-scratch"
LIBRARY_NAME = "Watcom"
LIBRARY_VERSION = "11.0c"

OWP4V1COPY_SHA = "52a4ed130e644761f6d1427e40dda4edf099adbf"
OWP4V1COPY_TARBALL_URL = f"https://github.com/open-watcom/owp4v1copy/archive/{OWP4V1COPY_SHA}.tar.gz"

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

INTERNAL_HEADERS_DIR = "internal_headers"
INTERNAL_HEADERS_FILE = "_watcom_internals.h"

WATCOM_DEFINES = [
	"__near=",
	"__far=",
	"__huge=",
	"__pascal=",
	"__stdcall=",
	"__fortran=",
	"__interrupt=",
	"__export=",
	"__loadds=",
	"__saveregs=",
	"__segment=unsigned",
	"__based(x)=",
	"__segname(x)=",
	"__declspec(x)=",

	"_WCRTLINK=",
	"_WCIRTLINK=",
	"_WCRTDATA=",
	"_WCNORETURN=",
	"_WCSHARED=",
	"_WCBUILTIN=",
	"_INTERNAL=",

	"__F_NAME(a,b)=a",

	"_ENABLE_AUTODEPEND=1",
	"__WATCOMC__=1100",
	"__STDC__=1"
]

# Per-model defines + cspec selection. The first list element is what gets
# passed to `-D` for that model.
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
			( "emu87.lib", "/16/emu87" ),
			( "graph.lib", "/16/graph" ),
			( "cstart_t.obj", "/16/startup" ),
			( "dos16m.obj", "/16/startup" ),
			( "binmode.obj", "/16/startup" ),
			( "commode.obj", "/16/startup" )
		],
		"variants": [
			( "/16/clib-s", "Real Mode (small)" ),
			( "/16/clib-m", "Real Mode (medium)" ),
			( "/16/clib-c", "Real Mode (compact)" ),
			( "/16/clib-l", "Real Mode (large)" ),
			( "/16/clib-h", "Real Mode (huge)" ),
			( "/16/clib-om", "Real Mode (medium, opt-size)" ),
			( "/16/clib-ol", "Real Mode (large, opt-size)" ),
			( "/16/emu87", "FPU emulation" ),
			( "/16/graph", "Graphics (16-bit)" ),
			( "/16/startup", "Startup (DOS 16-bit)" )
		]
	},
	{
		"tag": "32",
		"arch": "d32",
		"env_override": "WATCOM_LIB32",
		"language": "x86:LE:32:default",
		"cspec": "watcom",
		"fidbf": "watcom32-libs.fidbf",
		"imports": [
			( "clib3r.lib", "/32/clib3-r" ),
			( "clib3s.lib", "/32/clib3-s" ),
			( "emu387.lib", "/32/emu387" ),
			( "graph.lib", "/32/graph" ),
			( "cstrtx3r.obj", "/32/startup-reg" ),
			( "adiestrt.obj", "/32/startup-reg" ),
			( "adifstrt.obj", "/32/startup-reg" ),
			( "cstrtx3s.obj", "/32/startup-stk" ),
			( "adsstart.obj", "/32/startup-stk" ),
			( "binmode.obj", "/32/startup-stk" ),
			( "commode.obj", "/32/startup-stk" )
		],
		"variants": [
			( "/32/clib3-r", "Flat 32 (register call)" ),
			( "/32/clib3-s", "Flat 32 (stack call)" ),
			( "/32/emu387", "FPU emulation" ),
			( "/32/graph", "Graphics (32-bit)" ),
			( "/32/startup-reg", "Startup (DOS 32-bit register)" ),
			( "/32/startup-stk", "Startup (DOS 32-bit stack)" )
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

def resolve_public_headers(override: str | None) -> Path:
	if override:
		path = Path(override)
		if not path.is_dir():
			sys.exit(f"error: {path} (header override) is not a directory")

		return path

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

	return raw

def resolve_internal_headers() -> Path:
	target = SCRATCH / f"owp4v1copy-{OWP4V1COPY_SHA[:7]}"
	marker = target / ".extracted"
	if marker.exists():
		apply_upstream_patches(target)
		return target

	tarball = SCRATCH / f"owp4v1copy-{OWP4V1COPY_SHA[:7]}.tar.gz"
	if not tarball.exists():
		print(f"[download] {OWP4V1COPY_TARBALL_URL}")
		urllib.request.urlretrieve(OWP4V1COPY_TARBALL_URL, tarball)

	target.mkdir(parents=True, exist_ok=True)
	print(f"[extract] {tarball.name} (internal-header subtrees only)")

	def is_wanted(parts: list[str]) -> bool:
		rel = parts[1:]
		if len(rel) < 3: return False
		if not (rel[-1].endswith(".h") or rel[-1].endswith(".hpp")): return False
		if rel[0] != "bld": return False

		return "h" in rel[:-1]

	count = 0
	with tarfile.open(tarball) as tf:
		for member in tf:
			if not member.isreg(): continue
			parts = member.name.split("/")
			if not is_wanted(parts): continue

			relative = Path(*parts[1:])
			destination = target / relative
			destination.parent.mkdir(parents=True, exist_ok=True)

			extracted = tf.extractfile(member)
			if extracted is None: continue
			destination.write_bytes(extracted.read())
			count += 1

	apply_upstream_patches(target)

	marker.touch()
	print(f"[extract] {count} internal headers extracted")
	return target

UPSTREAM_PATCHES = [
	(
		"bld/clib/process/h/memblk.h",
		[ (
			"byte                unkown[11]\n",
			"byte                unkown[11];\n"
		) ]
	),
]

def apply_upstream_patches(target: Path) -> None:
	for rel, edits in UPSTREAM_PATCHES:
		path = target / rel
		if not path.is_file(): continue

		body = path.read_text(encoding="utf-8")
		patched = body

		for needle, replacement in edits:
			patched = patched.replace(needle, replacement)

		if patched != body:
			path.write_text(patched, encoding="utf-8")
			print(f"[patch] {rel}")


CRT_CATEGORY_COMPONENTS = {
	"heap": "heap",
	"streamio": "stdio",
	"file": "stdio",
	"handleio": "stdio",
	"process": "process",
	"startup": "startup",
}

CRT_CATEGORY_META_HEADERS = {
	"heapacc.h": "heap",
	"_environ.h": "process",
	"initarg.h": "startup",
	"close.h": "stdio",
	"lseek.h": "stdio",
	"openmode.h": "stdio",
	"fileacc.h": "stdio",
	"filestr.h": "stdio",
	"_doslfn.h": "stdio",
	"seterrno.h": "stdio",
	"iomode.h": "stdio",
}

def category_of_header_path(path: str) -> str | None:
	parts = Path(path).parts
	if "clib" not in parts: return None

	idx = parts.index("clib")
	if idx + 1 >= len(parts): return None

	tail = parts[idx + 1]
	if tail == "h":
		if idx + 2 < len(parts):
			return CRT_CATEGORY_META_HEADERS.get(parts[idx + 2])

		return None

	return CRT_CATEGORY_COMPONENTS.get(tail)

def generate_crt_categories(public_dir: Path, internal_root: Path, stub_dir: Path) -> dict:
	small_defines = next(t[1] for t in GDT_TARGETS if t[0] == "small")
	clang_args = build_clang_args(public_dir, internal_root, stub_dir, small_defines)

	master = SCRATCH / "_categories_master.h"
	master.write_text(generate_master_header(DOS_HEADERS, internal_root), encoding="utf-8")

	index = clang.cindex.Index.create()
	tu = index.parse(
			str(master),
			args=clang_args,
			options=clang.cindex.TranslationUnit.PARSE_SKIP_FUNCTION_BODIES)

	for diagnostic in tu.diagnostics:
		if diagnostic.severity >= clang.cindex.Diagnostic.Error:
			location = diagnostic.location
			print(f"[crt-categories] {diagnostic.spelling} at "
				f"{location.file.name if location.file else '?'}:{location.line}")

	out: dict[str, set[str]] = {cat: set() for cat in set(CRT_CATEGORY_COMPONENTS.values())}
	for cursor in tu.cursor.walk_preorder():
		if cursor.kind != clang.cindex.CursorKind.FUNCTION_DECL:
			continue

		if cursor.location.file is None:
			continue

		category = category_of_header_path(cursor.location.file.name)
		if category is None:
			continue

		name = cursor.spelling
		if not name: continue

		out.setdefault(category, set()).add(name)
		out[category].add(name + "_")
		if not name.startswith("_"):
			out[category].add("_" + name)

	return { cat: sorted(names) for cat, names in out.items() if names }

AUX_CALLER_RE = re.compile(
	r'^\s*#\s*pragma\s+aux\s+([A-Za-z_][A-Za-z0-9_]*)\b[^\n]*\b(?:__)?caller\b',
	re.MULTILINE)

AUX_ABORTS_RE = re.compile(
	r'^\s*#\s*pragma\s+aux\s+([A-Za-z_][A-Za-z0-9_]*)\b[^\n]*\b(?:__)?aborts\b',
	re.MULTILINE)

ALL_PRAGMA_RE = re.compile(r'^\s*#\s*pragma\b[^\n]*\n', re.MULTILINE)

INTERNAL_COMPONENT_BLACKLIST = {
	"defwin",
	"mthread",
	"win386",
	"kanji",
	"mbyte"
}

INTERNAL_FILE_BLACKLIST = {
	"libwin32.h",
	"_defwin.h",
	"defwin.h",
	"dll.h",

	"linuxsys.h",
	"syslinux.h",
	"sys386.h",
	"sysmips.h",
	"os2fil64.h",
	"tinyos2.h",
	"nonx86.h",
	"riscstr.h",
	"rtcheck.h",
	"sigtab.h",
	"mthread.h",

	"osthread.h",
	"thread.h",
	"sigdefn.h",
	"ntex.h",
	"rdosex.h",
	"dm_pts.h",

	"saferlib.h",
	"prtscncf.h",
}

INTERNAL_FILE_BLACKLIST_PATTERNS = (
	"*wnt.h", "*os2.h", "*rdu.h", "*lin.h", "*qnx.h", "*nw.h",
)

HEADER_STUBS = {
	"stdint.h": """
typedef signed char int8_t;
typedef unsigned char uint8_t;
typedef short int16_t;
typedef unsigned short uint16_t;
typedef int int32_t;
typedef unsigned int uint32_t;
typedef long long int64_t;
typedef unsigned long long uint64_t;
typedef long intptr_t;
typedef unsigned long uintptr_t;
typedef long long intmax_t;
typedef unsigned long long uintmax_t;
""",
	"stdbool.h": """
typedef int bool;
#define true 1
#define false 0
""",
}

def generate_master_header(public_headers: list[str], internal_root: Path) -> str:
	lines = []
	for header in public_headers:
		lines.append(f'#include <{header}>')

	clib_root = internal_root / "bld" / "clib"

	meta_headers = sorted((clib_root / "h").glob("*.h")) if(clib_root / "h").is_dir() else []
	per_component = sorted(clib_root.glob("*/h/*.h"))

	lib_misc_h = internal_root / "bld" / "lib_misc" / "h"
	lib_misc_headers = sorted(lib_misc_h.glob("*.h")) if lib_misc_h.is_dir() else []

	for header in meta_headers + per_component + lib_misc_headers:
		if header.name in INTERNAL_FILE_BLACKLIST:
			continue
		if any(fnmatch.fnmatchcase(header.name, p) for p in INTERNAL_FILE_BLACKLIST_PATTERNS):
			continue

		try:
			component = header.parts[header.parts.index("clib") + 1]
		except (ValueError, IndexError):
			component = None

		if component in INTERNAL_COMPONENT_BLACKLIST:
			continue

		lines.append(f'#include "{header}"')

	return "\n".join(lines) + "\n"

def strip_pragma_continuations(text: str) -> str:
	out = []
	in_pragma_continuation = False
	pragma_lead = re.compile(r'^\s*#\s*pragma\b')

	lines = text.splitlines(keepends=True)
	for line in lines:
		if in_pragma_continuation:
			if not line.rstrip("\n").endswith("\\"):
				in_pragma_continuation = False

			continue

		if pragma_lead.match(line):
			if line.rstrip("\n").endswith("\\"):
				in_pragma_continuation = True
			out.append(line)

			continue

		out.append(line)

	return "".join(out)

def inject_cdecl(text: str, names: set[str]) -> str:
	for name in names:
		pattern = re.compile(
			rf'\b(extern)\b([^;{{}}]*?)\b{re.escape(name)}\s*\(',
			re.MULTILINE | re.DOTALL)

		def replace(match):
			prefix = match.group(2)
			if "__cdecl" in prefix:
				return match.group(0)

			return f"{match.group(1)} __cdecl{prefix}{name}("

		text = pattern.sub(replace, text)

	return text

def ensure_stub_dir() -> Path:
	stub_dir = SCRATCH / "header_stubs"
	stub_dir.mkdir(parents=True, exist_ok=True)

	for name, body in HEADER_STUBS.items():
		(stub_dir / name).write_text(body.lstrip(), encoding="utf-8")

	return stub_dir

def build_clang_args(
		public_dir: Path,
		internal_root: Path,
		stub_dir: Path,
		model_defines: list[str]) -> list[str]:

	args = [
		"-x", "c",
		"-nostdinc",
		"-undef",
		"-w",
		"-I", str(public_dir),
		"-I", str(public_dir / "sys"),
		"-I", str(stub_dir),
	]

	bld_root = internal_root / "bld"
	for header_dir in sorted(bld_root.glob("**/h")):
		if header_dir.is_dir():
			args.extend(["-I", str(header_dir)])

	args.extend(["-include", "variety.h", "-include", "widechar.h"])
	for define in model_defines + WATCOM_DEFINES:
		args.append(f"-D{define}")

	return args

def preprocess_headers(
		public_dir: Path,
		internal_root: Path,
		model_defines: list[str],
		preprocessed_out: Path,
		noreturn_out: Path,
		label: str) -> bool:

	cc = os.environ.get("CC", "clang")
	stub_dir = ensure_stub_dir()

	master = preprocessed_out.with_suffix(".master.h")
	master.write_text(generate_master_header(DOS_HEADERS, internal_root), encoding="utf-8")

	clang_args = build_clang_args(public_dir, internal_root, stub_dir, model_defines)

	cmd = [ cc, "-E", "-P", *clang_args, str(master) ]

	print(f"[{label}] preprocessing via {cc}")
	try:
		result = subprocess.run(cmd, capture_output=True, text=True, check=True)
	except subprocess.CalledProcessError as exception:
		print(f"[{label}] {cc} -E FAILED:")
		print(exception.stderr, file=sys.stderr)

		return False

	preprocessed = result.stdout

	preprocessed = re.sub(
		r'(#\s*pragma\s+pack\s*\()__push\b',
		r'\1push',
		preprocessed)

	preprocessed = re.sub(
		r'(#\s*pragma\s+pack\s*\()__pop\b',
		r'\1pop',
		preprocessed)

	preprocessed = re.sub(
		r'(#\s*pragma\s+pack\s*\([^\n]*\));',
		r'\1',
		preprocessed)

	cdecl_names = set(AUX_CALLER_RE.findall(preprocessed))
	noreturn_names = set(AUX_ABORTS_RE.findall(preprocessed))

	pack_lines = []
	def stash_pack(match):
		pack_lines.append((len(pack_lines), match.group(0)))
		return f"\n/*__PACK_PLACEHOLDER_{len(pack_lines) - 1}__*/\n"

	preprocessed = re.sub(
		r'^\s*#\s*pragma\s+pack\b[^\n]*\n',
		stash_pack,
		preprocessed,
		flags=re.MULTILINE)

	preprocessed = strip_pragma_continuations(preprocessed)
	preprocessed = ALL_PRAGMA_RE.sub("", preprocessed)

	for index, line in pack_lines:
		preprocessed = preprocessed.replace(
			f"/*__PACK_PLACEHOLDER_{index}__*/",
			line.rstrip("\n"),
			1)

	preprocessed = inject_cdecl(preprocessed, cdecl_names)

	internal_supplement = Path(__file__).resolve().parent / INTERNAL_HEADERS_DIR / INTERNAL_HEADERS_FILE
	if internal_supplement.is_file():
		supplement_text = internal_supplement.read_text(encoding="utf-8")

		override_names = re.findall(
			r'\bextern\b[^;{}]*?\b([A-Za-z_][A-Za-z0-9_]*)\s*\(',
			supplement_text)

		for name in set(override_names):
			preprocessed = re.sub(
				rf'^\s*(?:_WCRTLINK\s+)?extern\b[^;{{}}]*?\b{re.escape(name)}\s*\([^;{{}}]*?\)\s*;[ \t]*\n',
				'',
				preprocessed,
				flags=re.MULTILINE)

		preprocessed += "\n/* === hand-authored declarations (overrides + asm-only) === */\n"
		preprocessed += supplement_text

	preprocessed_out.write_text(preprocessed, encoding="utf-8")
	noreturn_out.write_text(
		"\n".join(sorted(noreturn_names)) + ("\n" if noreturn_names else ""),
		encoding="utf-8")

	print(f"[{label}] preprocessed {len(preprocessed)} bytes; "
		f"cdecl={len(cdecl_names)}, noreturn={len(noreturn_names)}")

	return True

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

def run_gdt_target(target: tuple, public_dir: Path, internal_dir: Path) -> bool:
	variant, defines, language_id, compiler_id, gdt_name = target
	label = f"gdt {variant}"

	gdt_path = GDT_DIR / gdt_name
	gdt_path.unlink(missing_ok=True)
	dump_path = GDT_DIR / f"{gdt_name}_CParser.out"
	dump_path.unlink(missing_ok=True)

	preprocessed = SCRATCH / f"preprocessed-{variant}.h"
	noreturn_sidecar_scratch = SCRATCH / f"preprocessed-{variant}.noreturn"

	if not preprocess_headers(
			public_dir, internal_dir, defines,
			preprocessed, noreturn_sidecar_scratch, label):
		return False

	noreturn_published = NORETURN_DIR / gdt_name.replace(".gdt", ".noreturn")
	shutil.copyfile(noreturn_sidecar_scratch, noreturn_published)

	print(f"[{label}] parsing into {gdt_path.name}")

	project_name = f"{PROJECT_NAME}-gdt-{variant}"
	script_args = [
		"-scriptPath", str(SCRIPTS),
		"-noanalysis",
		"-preScript", "ParseHeadersToGdt.java",
		str(gdt_path),
		str(preprocessed),
		language_id,
		compiler_id,
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
NORETURN_DIR.mkdir(parents=True, exist_ok=True)

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
	public_dir = resolve_public_headers(os.environ.get("WATCOM_HDR"))
	internal_dir = resolve_internal_headers()
	print(f"[gdt] public headers: {public_dir}")
	print(f"[gdt] internal headers: {internal_dir}")
	jobs += [ ( "gdt", ( target, public_dir, internal_dir ) ) for target in GDT_TARGETS ]

	categories = generate_crt_categories(public_dir, internal_dir, ensure_stub_dir())
	CATEGORIES_FILE.parent.mkdir(parents=True, exist_ok=True)
	CATEGORIES_FILE.write_text(json.dumps(categories, indent="\t") + "\n", encoding="utf-8")

	print(f"[crt-categories] wrote {CATEGORIES_FILE.name}: " + ", ".join(f"{cat}={len(names)}" for cat, names in categories.items()))

def dispatch(job):
	kind, payload = job
	if kind == "fid":
		run_fid_pipeline(payload)
		return True

	target, public_dir, internal_dir = payload

	return run_gdt_target(target, public_dir, internal_dir)

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
