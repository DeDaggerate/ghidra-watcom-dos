// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Emily "TTG" Banerjee <prs.ttg+dedagger@pm.me>

package watcomdos;

import java.util.ArrayDeque;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Queue;
import java.util.Set;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;

import ghidra.framework.options.Options;

import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.SourceType;

import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class WatcomCrtPropagationAnalyzer extends AbstractAnalyzer {
	private static final String NAME = "Watcom CRT Call-Graph Propagation";
	private static final String DESCRIPTION =
			"Marks DEFAULT-named (FUN_xxxx) functions as 'likely Watcom CRT internal' when their entire " +
			"caller set is already known runtime code (FID-matched / loader-imported / WatcomDosStartup-renamed). " +
			"Non-destructive: adds a bookmark + plate comment, never renames. Useful for filtering the " +
			"function list to actual user code on stripped Watcom DOS binaries.";

	private static final String BOOKMARK_CATEGORY = "WatcomCRT";
	private static final String BOOKMARK_NOTE_PROPAGATED =
			"likely Watcom CRT internal (call-graph reachable only through named runtime functions)";
	private static final String BOOKMARK_NOTE_SYSCALL =
			"likely Watcom CRT internal (contains raw DOS syscall; user code routes through clib wrappers)";

	private static final String PLATE_PROPAGATED =
			"Likely Watcom CRT internal; all callers are named runtime functions.\n" +
			"Marked by Watcom CRT Call-Graph Propagation. Rename to override.";
	private static final String PLATE_SYSCALL =
			"Likely Watcom CRT internal; contains raw DOS INT (AH=%s).\n" +
			"User code routes DOS calls through clib wrappers; raw INT is a strong CRT signal.\n" +
			"Marked by Watcom CRT Call-Graph Propagation. Rename to override.";

	private static final Set<Integer> CRT_DOS_VECTORS = new HashSet<>(Arrays.asList(
			0x21,
			0x25,
			0x26,
			0x2f,
			0x31,
			0x33
	));


	public WatcomCrtPropagationAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.FUNCTION_ANALYZER);

		setPriority(AnalysisPriority.FUNCTION_ID_ANALYSIS.after().after().after().after());
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

		FunctionManager functionManager = program.getFunctionManager();
		Listing listing = program.getListing();

		Set<Function> crt = new HashSet<>();
		Queue<Function> work = new ArrayDeque<>();
		Map<Function, Integer> syscallAh = new HashMap<>();

		for(Function function : functionManager.getFunctions(true)) {
			monitor.checkCancelled();
			if(isSeed(function)) {
				crt.add(function);
				work.add(function);
			}
		}
		int seedCount = crt.size();

		int syscallSeeds = 0;
		for(Function function : functionManager.getFunctions(true)) {
			monitor.checkCancelled();
			if(function.getSymbol().getSource() != SourceType.DEFAULT) continue;
			if(function.isThunk() || function.isExternal()) continue;
			if(crt.contains(function)) continue;

			Integer ah = findCrtSyscallAh(listing, function);
			if(ah != null) {
				crt.add(function);
				work.add(function);
				syscallAh.put(function, ah);
				syscallSeeds++;
			}
		}

		while(!work.isEmpty()) {
			monitor.checkCancelled();
			Function recentlyAdded = work.poll();

			for(Function callee : recentlyAdded.getCalledFunctions(monitor)) {
				if(crt.contains(callee)) continue;
				if(callee.getSymbol().getSource() != SourceType.DEFAULT) continue;
				if(callee.isThunk() || callee.isExternal()) continue;

				Set<Function> callers = callee.getCallingFunctions(monitor);
				if(callers.isEmpty()) continue;

				boolean allCrt = true;
				for(Function caller : callers) {
					if(!crt.contains(caller)) { allCrt = false; break; }
				}

				if(allCrt) {
					crt.add(callee);
					work.add(callee);
				}
			}
		}

		int marked = 0;
		for(Function function : crt) {
			if(function.getSymbol().getSource() != SourceType.DEFAULT) continue;
			try {
				Integer ah = syscallAh.get(function);
				String bookmarkNote = ah != null ? BOOKMARK_NOTE_SYSCALL : BOOKMARK_NOTE_PROPAGATED;
				String plate = ah != null
						? String.format(PLATE_SYSCALL, String.format("0x%02x", ah))
						: PLATE_PROPAGATED;

				program.getBookmarkManager().setBookmark(
						function.getEntryPoint(),
						BookmarkType.ANALYSIS,
						BOOKMARK_CATEGORY,
						bookmarkNote);

				String existing = listing.getComment(CommentType.PLATE, function.getEntryPoint());
				if(existing == null || !existing.contains("Watcom CRT")) {
					listing.setComment(function.getEntryPoint(), CommentType.PLATE, plate);
				}

				marked++;
			}
			catch(Exception exception) {
				log.appendMsg(NAME, "mark " + function.getEntryPoint() + ": " + exception.getMessage());
			}
		}

		log.appendMsg(
				NAME,
				"seeded " +
				seedCount +
				" named runtime functions + " +
				syscallSeeds + " DOS syscall wrappers; propagated to " +
				marked + " total FUN_ functions (bookmarked under '" +
				BOOKMARK_CATEGORY +
				"')");

		return true;
	}

	private static Integer findCrtSyscallAh(Listing listing, Function function) {
		InstructionIterator it = listing.getInstructions(function.getBody(), true);
		int lastAh = -1;
		while(it.hasNext()) {
			Instruction instruction = it.next();
			String mnemonic = instruction.getMnemonicString();

			if("MOV".equals(mnemonic) && instruction.getNumOperands() == 2) {
				String op0 = instruction.getDefaultOperandRepresentation(0);
				Object[] objs = instruction.getOpObjects(1);
				if(objs.length > 0 && objs[0] instanceof Scalar) {
					long imm = ((Scalar) objs[0]).getValue();
					if("AH".equals(op0)) lastAh = (int) imm & 0xff;
					else if("AX".equals(op0) || "EAX".equals(op0)) lastAh = (int) (imm >> 8) & 0xff;
				}
			}

			if("INT".equals(mnemonic) && instruction.getNumOperands() >= 1) {
				Object[] objs = instruction.getOpObjects(0);
				if(objs.length > 0 && objs[0] instanceof Scalar) {
					int vec = (int) ((Scalar) objs[0]).getValue() & 0xff;
					if(CRT_DOS_VECTORS.contains(vec)) {
						return lastAh >= 0 ? lastAh : vec;
					}
				}
			}
		}

		return null;
	}

	private static boolean isSeed(Function function) {
		if(function.isExternal() || function.isThunk()) return false;

		SourceType source = function.getSymbol().getSource();
		if(source == SourceType.DEFAULT) return false;

		if(WatcomCrtAnchors.USER_CODE_ANCHORS.contains(function.getName())) return false;

		return true;
	}
}
