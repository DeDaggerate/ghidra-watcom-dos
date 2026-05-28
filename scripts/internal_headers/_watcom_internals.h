/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 Emily "TTG" Banerjee <prs.ttg+dedagger@pm.me> */

extern int __cdecl __dospawn(int mode, char *path, char *cmdline, char *envp);

extern void __fatal_runtime_error(char *msg, unsigned exit_code);

extern char *__Slash_C(char *switch_c, int use_slash);
