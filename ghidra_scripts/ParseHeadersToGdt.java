// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Emily "TTG" Banerjee <prs.ttg+dedagger@pm.me>

//@category WatcomDOS

import java.io.File;

import ghidra.app.script.GhidraScript;
import ghidra.app.util.cparser.C.CParserUtils;
import ghidra.program.model.data.FileDataTypeManager;
import ghidra.util.task.TaskMonitor;

public class ParseHeadersToGdt extends GhidraScript {
	@Override
	protected void run() throws Exception {
		String[] arguments = getScriptArgs();
		if(arguments.length != 4) {
			printerr("Usage: ParseHeadersToGdt <out.gdt> <preprocessed.h> <languageId> <compilerId>");
			printerr("Got: " + java.util.Arrays.toString(arguments));
			return;
		}

		File outFile = new File(arguments[0]);
		File preprocessed = new File(arguments[1]);
		String languageId = arguments[2];
		String compilerId = arguments[3];

		if(!preprocessed.isFile()) {
			printerr("Not a file: " + preprocessed);
			return;
		}

		if(outFile.exists() && !outFile.delete()) {
			printerr("error: cannot overwrite " + outFile);
			return;
		}

		TaskMonitor taskMonitor = monitor != null ? monitor : TaskMonitor.DUMMY;

		println("[+] parsing " + preprocessed.getName() + " -> " + outFile.getName() +
				" (" + languageId + " / " + compilerId + ")");

		FileDataTypeManager dataTypeManager = CParserUtils.parseHeaderFiles(
				null,
				new String[] { preprocessed.getAbsolutePath() },
				new String[0],
				new String[0],
				outFile.getAbsolutePath(),
				languageId,
				compilerId,
				taskMonitor);

		try {
			println(
					"[+] wrote " +
					outFile +
					" (" +
					outFile.length() +
					" bytes, " +
					dataTypeManager.getDataTypeCount(true) +
					" types)");
		}
		finally {
			dataTypeManager.close();
		}
	}
}
