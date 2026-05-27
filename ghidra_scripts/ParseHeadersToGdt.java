// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Emily "TTG" Banerjee <prs.ttg+dedagger@pm.me>

//@category WatcomDOS

import java.io.File;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.script.GhidraScript;
import ghidra.app.util.cparser.C.CParserUtils;
import ghidra.program.model.data.FileDataTypeManager;
import ghidra.util.task.TaskMonitor;

public class ParseHeadersToGdt extends GhidraScript {
	@Override
	protected void run() throws Exception {
		String[] arguments = getScriptArgs();
		if(arguments.length != 6) {
			printerr("Usage: ParseHeadersToGdt <out.gdt> <includeDir> <languageId> <compilerId> <defines;...> <headers;...>");
			printerr("Got: " + java.util.Arrays.toString(arguments));
			return;
		}

		File outFile = new File(arguments[0]);
		File includeDir = new File(arguments[1]);
		String languageId = arguments[2];
		String compilerId = arguments[3];
		String[] defines = arguments[4].isEmpty() ? new String[0] : arguments[4].split(";");
		String[] headerNames = arguments[5].split(";");

		if(!includeDir.isDirectory()) {
			printerr("Not a directory: " + includeDir);
			return;
		}

		List<String> compilerArguments = new ArrayList<>();
		compilerArguments.add("-v0");
		for(String define : defines) {
			if(!define.isEmpty()) compilerArguments.add("-D" + define);
		}

		String[] includePaths = new String[] {
				includeDir.getAbsolutePath(),
				new File(includeDir, "sys").getAbsolutePath(),
		};

		String[] filenames = new String[headerNames.length];
		for(int i = 0; i < headerNames.length; i++) {
			File header = new File(includeDir, headerNames[i]);
			if(!header.isFile()) {
				println("[-] skip (missing): " + headerNames[i]);
				filenames[i] = "#" + headerNames[i] + " (missing)";
				continue;
			}

			filenames[i] = header.getAbsolutePath();
		}

		if(outFile.exists() && !outFile.delete()) {
			printerr("error: cannot overwrite " + outFile);
			return;
		}

		TaskMonitor taskMonitor = monitor != null ? monitor : TaskMonitor.DUMMY;

		println("[+] parsing " + headerNames.length + " headers -> " + outFile.getName() +
				" (" + languageId + " / " + compilerId + ")");

		FileDataTypeManager dataTypeManager = CParserUtils.parseHeaderFiles(
				null,
				filenames,
				includePaths,
				compilerArguments.toArray(new String[0]),
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
