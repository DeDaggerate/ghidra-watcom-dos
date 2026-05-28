// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Emily "TTG" Banerjee <prs.ttg+dedagger@pm.me>

package watcomdos;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;

import ghidra.framework.options.Options;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;

import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class WatcomDosStartupAnalyzer extends AbstractAnalyzer {
	private static final String NAME = "Watcom DOS Startup Recognition";
	private static final String DESCRIPTION =
			"For Watcom-compiled DOS programs: detect the Watcom C-runtime startup function by its NO87 " +
			"environment-variable scan, rename it to __cstart_, and identify the user main it calls into.";

	private static final byte[] NO87_LOW = { (byte) 0x6e, (byte) 0x6f };
	private static final byte[] NO87_HIGH = { (byte) 0x38, (byte) 0x37 };

	private static final int SCAN_BYTES = 2048;
	private static final int INIT_MAIN_MAX_DISTANCE = 16;
	private static final int MAIN_FINI_MAX_DISTANCE = 256;

	private static final String CSTART_NAME = "__cstart_";
	private static final String INIT_NAME = "__InitRtns_";
	private static final String MAIN_NAME = "main_";
	private static final String FINI_NAME = "__FiniRtns_";

	private static final String BOOKMARK_CATEGORY_USER = "WatcomMain";
	private static final String BOOKMARK_CATEGORY_CRT = "WatcomCRT";
	private static final String BOOKMARK_NOTE_MAIN = "user main(); Watcom CRT hand-off point";
	private static final String BOOKMARK_NOTE_CSTART =
			"Watcom C-runtime entry (_cstart_); calls __InitRtns_ -> main -> __FiniRtns_";

	private static final String BOOKMARK_NOTE_INIT =
			"Watcom static initialiser table walker (__InitRtns_)";

	private static final String BOOKMARK_NOTE_FINI =
			"Watcom static finaliser table walker (__FiniRtns_); runs on main's return";

	private static final String PLATE_MAIN =
			"User main(); Watcom CRT hand-off point.\n" +
			"Called by __cstart_ after __InitRtns_ completes; CRT resumes with __FiniRtns_ on return.\n" +
			"This is where the actual program logic begins.\n" +
			"Marked by Watcom DOS Startup Recognition.";

	private static final String PLATE_CSTART =
			"Watcom C-runtime entry (_cstart_).\n" +
			"Sets up DGROUP, env/argv, NO87 check, then calls:\n" +
			"  __InitRtns_  (static initialisers)\n" +
			"  main()       (user code)\n" +
			"  __FiniRtns_  (static finalisers, on return)\n" +
			"Marked by Watcom DOS Startup Recognition.";

	private static final String PLATE_INIT =
			"Watcom static initialiser walker (__InitRtns_).\n" +
			"Iterates the __XI table installing C++/static-storage initialisers.\n" +
			"Marked by Watcom DOS Startup Recognition.";

	private static final String PLATE_FINI =
			"Watcom static finaliser walker (__FiniRtns_).\n" +
			"Iterates the __YI table running atexit/static destructors after main returns.\n" +
			"Marked by Watcom DOS Startup Recognition.";

	private static final Set<String> LOADER_DEFAULT_NAMES = new HashSet<>(Arrays.asList(
			"entry",
			"_entry",
			"start",
			"_start",
			"_mainCRTStartup"
	));

	public WatcomDosStartupAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.FUNCTION_ANALYZER);

		setPriority(AnalysisPriority.FUNCTION_ID_ANALYSIS.after().after().after());
		setDefaultEnablement(true);
	}

	@Override
	public boolean canAnalyze(Program program) {
		String id = program.getCompilerSpec().getCompilerSpecID().getIdAsString();
		return "watcom".equals(id) || "watcom16".equals(id) || "watcom16far".equals(id);
	}

	@Override
	public void registerOptions(Options options, Program program) {}

	@Override
	public boolean added(
			Program program,
			AddressSetView set,
			TaskMonitor monitor,
			MessageLog log) throws CancelledException {

		Function cstart = findCstart(program, monitor);
		if(cstart == null) {
			log.appendMsg(NAME, "no Watcom _cstart_ signature found; skipping");
			return true;
		}

		Address cstartAddress = cstart.getEntryPoint();
		boolean renamedCstart = renameIfRenameable(cstart, CSTART_NAME, log);
		markFunction(program, cstart, BOOKMARK_CATEGORY_CRT, BOOKMARK_NOTE_CSTART, PLATE_CSTART, log);

		AddressSetView range = estimatedRange(cstart);
		List<CallSite> callSites = orderedDefaultCalls(program, range, monitor);
		CallTriple triple = findInitMainFiniTriple(callSites);
		if(triple == null) {
			log.appendMsg(
					NAME,
					(renamedCstart ? "renamed " : "found ") + CSTART_NAME + " @ " + cstartAddress +
					"; couldn't locate init->main->fini call triple in " + callSites.size() +
					" candidate calls; main detection skipped");

			return true;
		}

		boolean renamedInit = renameIfRenameable(triple.init.target, INIT_NAME, log);
		boolean renamedMain = renameIfRenameable(triple.main.target, MAIN_NAME, log);
		boolean renamedFini = renameIfRenameable(triple.fini.target, FINI_NAME, log);

		markFunction(program, triple.init.target, BOOKMARK_CATEGORY_CRT, BOOKMARK_NOTE_INIT, PLATE_INIT, log);
		markFunction(program, triple.main.target, BOOKMARK_CATEGORY_USER, BOOKMARK_NOTE_MAIN, PLATE_MAIN, log);
		markFunction(program, triple.fini.target, BOOKMARK_CATEGORY_CRT, BOOKMARK_NOTE_FINI, PLATE_FINI, log);

		log.appendMsg(
				NAME,
				(renamedCstart ? "renamed " : "kept ") + cstart.getName() + " @ " + cstartAddress +
				"; " + (renamedMain ? "renamed " : "kept ") + triple.main.target.getName() +
				" @ " + triple.main.target.getEntryPoint() +
				" (init: " + (renamedInit ? "renamed" : "kept") +
				", fini: " + (renamedFini ? "renamed" : "kept") + ")");

		return true;
	}

	private static class CallSite {
		final Address from;
		final Function target;
		CallSite(Address from, Function target) { this.from = from; this.target = target; }
	}

	private static class CallTriple {
		final CallSite init;
		final CallSite main;
		final CallSite fini;
		CallTriple(CallSite i, CallSite m, CallSite f) { init = i; main = m; fini = f; }
	}

	private static CallTriple findInitMainFiniTriple(List<CallSite> calls) {
		for(int i = 0; i < calls.size() - 2; i++) {
			CallSite a = calls.get(i);
			CallSite b = calls.get(i + 1);
			long abDistance = signedDistance(a.from, b.from);
			if(abDistance < 0 || abDistance > INIT_MAIN_MAX_DISTANCE) continue;

			for(int j = i + 2; j < calls.size(); j++) {
				CallSite c = calls.get(j);
				long bcDistance = signedDistance(b.from, c.from);
				if(bcDistance < 0) break;
				if(bcDistance > MAIN_FINI_MAX_DISTANCE) break;

				if(a.target.equals(b.target) || b.target.equals(c.target) || a.target.equals(c.target)) {
					continue;
				}
				return new CallTriple(a, b, c);
			}
		}
		return null;
	}

	private static long signedDistance(Address from, Address to) {
		try {
			return to.subtract(from);
		}
		catch(IllegalArgumentException differentSpace) {
			return -1;
		}
	}

	private Function findCstart(Program program, TaskMonitor monitor) throws CancelledException {
		SymbolTable symbolTable = program.getSymbolTable();
		FunctionManager functionManager = program.getFunctionManager();

		Set<Function> candidates = new LinkedHashSet<>();
		for(Address address : symbolTable.getExternalEntryPointIterator()) {
			monitor.checkCancelled();

			Function function = functionManager.getFunctionAt(address);
			if(function != null) candidates.add(function);
		}

		for(Function function : candidates) {
			monitor.checkCancelled();

			AddressSetView range = estimatedRange(function);
			if(rangeContainsBytes(program, range, NO87_LOW, monitor)
					&& rangeContainsBytes(program, range, NO87_HIGH, monitor)) {
				return function;
			}
		}

		return null;
	}

	private AddressSetView estimatedRange(Function function) {
		Address start = function.getEntryPoint();
		Address spaceMax = start.getAddressSpace().getMaxAddress();
		Address end;
		try {
			end = start.addNoWrap(SCAN_BYTES);
			if(end.compareTo(spaceMax) > 0) end = spaceMax;
		}
		catch(ghidra.program.model.address.AddressOverflowException overflow) {
			end = spaceMax;
		}
		return new AddressSet(start, end);
	}

	private static boolean rangeContainsBytes(
			Program program, AddressSetView range, byte[] needle, TaskMonitor monitor)
			throws CancelledException {

		Address cursor = range.getMinAddress();
		Address last = range.getMaxAddress();
		while(cursor != null && cursor.compareTo(last) <= 0) {
			monitor.checkCancelled();

			Address found = program.getMemory().findBytes(cursor, last, needle, null, true, monitor);
			if(found == null) return false;
			if(range.contains(found)) return true;
			cursor = found.next();
		}
		return false;
	}

	private List<CallSite> orderedDefaultCalls(
			Program program,
			AddressSetView range,
			TaskMonitor monitor) throws CancelledException {

		FunctionManager functionManager = program.getFunctionManager();
		Listing listing = program.getListing();

		List<CallSite> result = new ArrayList<>();
		InstructionIterator it = listing.getInstructions(range, true);
		while(it.hasNext()) {
			monitor.checkCancelled();

			Instruction instruction = it.next();
			if(!instruction.getFlowType().isCall()) continue;

			for(Reference reference : instruction.getReferencesFrom()) {
				if(!reference.getReferenceType().isCall()) continue;

				Function called = functionManager.getFunctionAt(reference.getToAddress());
				if(called == null) continue;
				if(called.isExternal()) continue;
				if(called.isThunk()) continue;
				if(called.getSymbol().getSource() != SourceType.DEFAULT) continue;

				result.add(new CallSite(instruction.getAddress(), called));
			}
		}

		return result;
	}

	private static void markFunction(
			Program program,
			Function function,
			String category,
			String note,
			String plate,
			MessageLog log) {

		try {
			program.getBookmarkManager().setBookmark(
					function.getEntryPoint(),
					BookmarkType.ANALYSIS,
					category,
					note);

			Listing listing = program.getListing();
			String existing = listing.getComment(CommentType.PLATE, function.getEntryPoint());
			if(existing == null || existing.contains("Watcom DOS Startup")) {
				listing.setComment(function.getEntryPoint(), CommentType.PLATE, plate);
			}
		}
		catch(Exception exception) {
			log.appendMsg(NAME, "mark " + function.getEntryPoint() + ": " + exception.getMessage());
		}
	}

	private static boolean renameIfRenameable(Function function, String newName, MessageLog log) {
		if(newName.equals(function.getName())) return false;

		Symbol symbol = function.getSymbol();
		SourceType source = symbol.getSource();

		if(source == SourceType.USER_DEFINED) return false;
		if(source == SourceType.IMPORTED && !LOADER_DEFAULT_NAMES.contains(function.getName())) return false;

		try {
			function.setName(newName, SourceType.ANALYSIS);
			return true;
		}
		catch(Exception exception) {
			log.appendMsg(NAME, "rename " + function.getEntryPoint() + " -> " + newName + ": " + exception.getMessage());
			return false;
		}
	}
}
