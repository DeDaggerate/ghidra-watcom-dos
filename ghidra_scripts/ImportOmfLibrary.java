// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Emily "TTG" Banerjee <prs.ttg+dedagger@pm.me>

//@category WatcomDOS

import java.io.File;
import java.nio.file.AccessMode;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.script.GhidraScript;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.ByteProviderWrapper;
import ghidra.app.util.bin.FileByteProvider;
import ghidra.app.util.bin.format.omf.AbstractOmfRecordFactory;
import ghidra.app.util.bin.format.omf.omf.OmfLibraryRecord;
import ghidra.app.util.bin.format.omf.omf.OmfRecordFactory;
import ghidra.app.util.importer.ProgramLoader;
import ghidra.app.util.opinion.LoadResults;
import ghidra.app.util.opinion.Loaded;
import ghidra.app.util.opinion.OmfLoader;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.Project;
import ghidra.framework.options.Options;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

public class ImportOmfLibrary extends GhidraScript {
	private static final byte OMF_LIBRARY_MAGIC = (byte) 0xF0;

	// Disabled to keep per-module analysis cheap: FID matching is irrelevant
	// (we're _building_ the FIDB, not matching against existing ones); decompiler-
	// driven passes and large data-archive lookups are pure overhead for OMF
	// objects whose hashes only need disassembly + function boundaries.
	private static final String[] DISABLED_ANALYZERS = {
			"Decompiler Parameter ID",
			"Decompiler Switch Analysis",
			"Function ID",
			"DWARF",
			"Apply Data Archives",
			"Embedded Media",
			"ASCII Strings",
	};

	@Override
	protected void run() throws Exception {
		String[] arguments = getScriptArgs();
		if(arguments.length < 4) {
			printerr("Usage: ImportOmfLibrary <ompFile> <projectFolder> <languageId> <compilerId>");
			printerr("Got: " + java.util.Arrays.toString(arguments));
			return;
		}

		File ompFile = new File(arguments[0]);
		String folderPath = arguments[1];
		String languageId = arguments[2];
		String compilerId = arguments[3];

		if(!ompFile.isFile()) {
			printerr("Not a file: " + ompFile);
			return;
		}

		Project project = state.getProject();
		if(project == null) {
			printerr("No active project");
			return;
		}

		TaskMonitor taskMonitor = monitor != null ? monitor : TaskMonitor.DUMMY;

		try(FileByteProvider provider = new FileByteProvider(ompFile, null, AccessMode.READ)) {
			byte firstByte = provider.readByte(0);
			if(firstByte == OMF_LIBRARY_MAGIC) {
				importArchive(provider, ompFile, folderPath, languageId, compilerId, project, taskMonitor);
			}
			else {
				importSingleModule(provider, ompFile, folderPath, languageId, compilerId, project, taskMonitor);
			}
		}
	}

	private void importArchive(
			FileByteProvider lib,
			File libFile,
			String folderPath,
			String languageId,
			String compilerId,
			Project project,
			TaskMonitor monitor) throws Exception {

		AbstractOmfRecordFactory factory = new OmfRecordFactory(lib);
		OmfLibraryRecord libraryRecord = OmfLibraryRecord.parse(factory, monitor);
		List<OmfLibraryRecord.MemberHeader> members = libraryRecord.getMemberHeaders();

		println("[+] " + libFile.getName() + " (archive): " + members.size() + " members");

		int imported = 0;
		int failed = 0;
		ArrayList<String> failures = new ArrayList<>();
		for(OmfLibraryRecord.MemberHeader member : members) {
			if(monitor.isCancelled()) break;

			String baseName = sanitize(member.name);
			try(ByteProviderWrapper provider = new ByteProviderWrapper(lib, member.payloadOffset, member.size, null)) {
				loadAndSave(
						provider,
						baseName,
						folderPath,
						languageId,
						compilerId,
						project,
						monitor);

				imported++;
			}
			catch(Exception exception) {
				failed++;
				failures.add(baseName + ": " + exception.getClass().getSimpleName() + ": " + exception.getMessage());
			}
		}

		println("[+] Imported " + imported + " / failed " + failed + " of " + members.size());
		for(String f : failures) printerr("\t- " + f);
	}

	private void importSingleModule(
			ByteProvider provider,
			File ompFile,
			String folderPath,
			String languageId,
			String compilerId,
			Project project,
			TaskMonitor monitor) throws Exception {

		String baseName = sanitize(stripExtension(ompFile.getName()));
		println("[+] " + ompFile.getName() + " (single module): importing as " + baseName);
		loadAndSave(provider, baseName, folderPath, languageId, compilerId, project, monitor);
		println("[+] Imported 1 of 1");
	}

	private void loadAndSave(
			ByteProvider provider,
			String name,
			String folderPath,
			String languageId,
			String compilerId,
			Project project,
			TaskMonitor monitor) throws Exception {

		LoadResults<Program> results = ProgramLoader.builder()
				.source(provider)
				.project(project)
				.projectFolderPath(folderPath)
				.name(name)
				.loaders(OmfLoader.class)
				.language(languageId)
				.compiler(compilerId)
				.monitor(monitor)
				.load();

		try {
			for(Loaded<Program> loaded : results) {
				Program program = loaded.getDomainObject();
				prepareAndAnalyze(program);
				DomainFile saved = loaded.save(monitor);
				println("\t+ " + saved.getPathname());
			}
		}
		finally {
			results.close();
		}
	}

	private void prepareAndAnalyze(Program program) {
		// One outer transaction covers both option mutation and auto-analysis;
		// AutoAnalysisManager.saveTaskTimes writes back to the options DB and
		// needs the program to be in a transactional state.
		int txId = program.startTransaction("Watcom FID prepare-and-analyze");
		try {
			Options options = program.getOptions("Analyzers");
			for(String name : DISABLED_ANALYZERS) {
				options.setBoolean(name, false);
			}
			analyzeAll(program);
		}
		finally {
			program.endTransaction(txId, true);
		}
	}

	private static String stripExtension(String name) {
		int dot = name.lastIndexOf('.');
		return dot > 0 ? name.substring(0, dot) : name;
	}

	private static String sanitize(String name) {
		if(name == null || name.isEmpty()) return "module";

		StringBuilder stringBuilder = new StringBuilder(name.length());

		for(int i = 0; i < name.length(); i++) {
			char c = name.charAt(i);

			if(c == '/' || c == '\\' || c == ':' || c == 0) {
				stringBuilder.append('_');
			}
			else {
				stringBuilder.append(c);
			}
		}

		return stringBuilder.toString();
	}
}
