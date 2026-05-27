# ghidra-watcom-dos

Watcom C/C++ DOS reverse-engineering support for
[Ghidra](https://github.com/NationalSecurityAgency/ghidra) 12.x.

Provides `.cspec` for Watcom 16-bit (`watcom16` for `x86:LE:16:Real Mode`)
and Watcom 32-bit (`watcom` for `x86:LE:32:default`), as well as function ID
databases built from Watcom 11.0c clib for DOS.

Built against Watcom 11.0c via. the release binaries provided at
[open-watcom/open-watcom-1.9](https://github.com/open-watcom/open-watcom-1.9/releases/tag/w11.0c-zips).

## Build & Install

1. Set the `GHIDRA_INSTALL_DIR` variable to point at your Ghidra installation.
2. Run `gradle buildExtension` to assemble the plugin at
`dist/ghidra-watcom-dos.zip`.
3. Run `scripts/install.py` to install the plugin and add the compiler
definitions for Watcom (not possible via. a pure extension). This may require
elevated privileges.

If you want to rebuild the function ID databases, run `scripts/build-fidb.py`;
this will output the required `.fidbf` files to `data/fidb` to be consumed by
a full plugin build. The process should take around 5 minutes.

## License

This file is part of
[ghidra-watcom-dos](https://github.com/DeDaggerate/ghidra-watcom-dos)
which is licenced under the Apache 2.0 licence.

The pre-generated `.fidbf` files are admissable as derived works of the Watcom
11.0c clib distribution, which Sybase released under the
[Sybase Open Watcom Public License](https://github.com/open-watcom/open-watcom-1.9/blob/master/LICENSE.TXT)
in 2002.
