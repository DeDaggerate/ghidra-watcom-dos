# ghidra-watcom-dos

Watcom C/C++ DOS reverse-engineering support for
[Ghidra](https://github.com/NationalSecurityAgency/ghidra) 12.x.

- Compiler specs for Watcom DOS targets:
	- `watcom16`: 16-bit real mode, near pointers (small / medium memory model)
	- `watcom16far`: 16-bit real mode, far pointers (compact / large / huge)
	- `watcom`: 32-bit flat (DOS extender)
- Function ID databases (`.fidb`) built from Watcom 11.0c clib for DOS.
- Per-memory-model C type-info archives (`.gdt`) parsed from the matching
Watcom headers. The analyzer attempts to tally which FID variant dominates the
program (small / medium / compact / large / huge / flat) and applies the
matching function signatures and structs. The model can be overridden via. the
"Memory model" analyzer option.
- An OMF `.lib` / `.obj` importer (`ImportOmfLibrary` ghidra_script) used by
the FID build pipeline.

Built against Watcom 11.0c via. the release zips at
[open-watcom/open-watcom-1.9](https://github.com/open-watcom/open-watcom-1.9/releases/tag/w11.0c-zips).

## Build & Install

1. Set the `GHIDRA_INSTALL_DIR` variable to point at your Ghidra installation.
2. Run `gradle buildExtension` to assemble the plugin at
`dist/ghidra-watcom-dos.zip`.
3. Run `scripts/install.py` to install the plugin and add the Watcom compiler
definitions to Ghidra's x86 language file (not possible via. a pure
extension). This may require elevated privileges.

## Rebuilding the data archives

The shipped `.fidbf` and `.gdt` files in `data/` are checked in, so end users
do not need to regenerate them. To rebuild them anyway:

1. Install the cspecs using `scripts/install.py --cspecs-only`
2. Build the `fidb` and `gdt` data using `scripts/build-data.py`.

The data is output into the tree ready for an extension build.

## License

This file is part of
[ghidra-watcom-dos](https://github.com/DeDaggerate/ghidra-watcom-dos)
which is licenced under the Apache 2.0 licence.

The pre-generated `.fidbf` and `.gdt` files are admissable as derived works
of the Watcom 11.0c clib + header distribution, which Sybase released under
the
[Sybase Open Watcom Public License](https://github.com/open-watcom/open-watcom-1.9/blob/master/LICENSE.TXT)
in 2002.
