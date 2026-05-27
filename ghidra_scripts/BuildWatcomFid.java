// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Emily "TTG" Banerjee <prs.ttg+dedagger@pm.me>

//@category WatcomDOS

import java.io.File;
import java.nio.file.Files;
import java.util.ArrayList;

import db.DBHandle;

import ghidra.app.script.GhidraScript;

import ghidra.feature.fid.db.FidDB;
import ghidra.feature.fid.db.FidFile;
import ghidra.feature.fid.db.FidFileManager;
import ghidra.feature.fid.service.FidService;

import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.Project;
import ghidra.framework.store.db.PackedDatabase;

import ghidra.program.database.ProgramContentHandler;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.Program;

import ghidra.util.task.TaskMonitor;

public class BuildWatcomFid extends GhidraScript {
	@Override
	protected void run() throws Exception {
		String[] arguments = getScriptArgs();
		if(arguments.length < 5 || (arguments.length - 3) % 2 != 0) {
			printerr("Usage: BuildWatcomFid <rawOut.fidbf> <libName> <libVersion> <folder1> <variant1> [<folder2> <variant2> ...]");
			printerr("Got: " + java.util.Arrays.toString(arguments));
			return;
		}

		File rawOut = new File(arguments[0]);
		String libName = arguments[1];
		String libVersion = arguments[2];

		Project project = state.getProject();
		if(project == null) {
			printerr("No active project");
			return;
		}

		TaskMonitor taskMonitor = monitor != null ? monitor : TaskMonitor.DUMMY;

		File scratch = Files.createTempFile("watcom-fid-", ".fidb").toFile();
		scratch.delete();

		FidFileManager fileManager = FidFileManager.getInstance();
		fileManager.createNewFidDatabase(scratch);

		FidFile fidFile = fileManager.addUserFidFile(scratch);
		FidDB fidDb = fidFile.getFidDB(true);
		boolean fidDbClosed = false;

		try {
			FidService service = new FidService();
			int variantsAdded = 0;
			for(int i = 3; i + 1 < arguments.length; i += 2) {
				String folderPath = arguments[i];
				String libVariant = arguments[i + 1];

				DomainFolder folder = project.getProjectData().getFolder(folderPath);
				if(folder == null) {
					println("[-] skip: folder not found: " + folderPath);
					continue;
				}

				ArrayList<DomainFile> programs = new ArrayList<>();
				findPrograms(programs, folder);
				if(programs.isEmpty()) {
					println("[-] skip: no programs under " + folderPath);
					continue;
				}

				LanguageID languageID;
				Program sample = (Program) programs.get(0).getDomainObject(this, false, false, taskMonitor);
				try {
					languageID = sample.getLanguageID();
				}
				finally {
					sample.release(this);
				}

				println("[+] " + folderPath + " (" + programs.size() + " programs, " + languageID + ')');
				var result = service.createNewLibraryFromPrograms(
						fidDb,
						libName,
						libVersion,
						libVariant,
						programs,
						null,
						languageID,
						null,
						null,
						taskMonitor);

				println("\t" + libVariant +
						": attempted = " + result.getTotalAttempted() +
						", added = " + result.getTotalAdded() +
						", excluded = " + result.getTotalExcluded());

				variantsAdded++;
			}

			if(variantsAdded == 0) {
				printerr("error: no variants populated; not writing " + rawOut);
				return;
			}

			if(rawOut.exists() && !rawOut.delete()) {
				printerr("error: cannot overwrite " + rawOut);
				return;
			}

			fidDb.saveDatabase("Building " + libName + ' ' + libVersion, taskMonitor);
			fidDb.close();
			fidDbClosed = true;

			PackedDatabase pdb = PackedDatabase.getPackedDatabase(scratch, false, taskMonitor);
			try {
				DBHandle handle = pdb.open(taskMonitor);
				try {
					handle.saveAs(rawOut, false, taskMonitor);
				}
				finally {
					handle.close();
				}
			}
			finally {
				pdb.dispose();
			}

			println("[+] wrote " + rawOut + " (" + rawOut.length() + " bytes)");
		}
		finally {
			if(!fidDbClosed) {
				fidDb.close();
			}

			fileManager.removeUserFile(fidFile);
			scratch.delete();
		}
	}

	private void findPrograms(ArrayList<DomainFile> programs, DomainFolder folder) {
		for(DomainFile f : folder.getFiles()) {
			if(f.getContentType().equals(ProgramContentHandler.PROGRAM_CONTENT_TYPE)) {
				programs.add(f);
			}
		}

		for(DomainFolder sub : folder.getFolders()) {
			findPrograms(programs, sub);
		}
	}
}
