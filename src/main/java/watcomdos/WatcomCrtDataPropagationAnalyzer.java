// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Emily "TTG" Banerjee <prs.ttg+dedagger@pm.me>

package watcomdos;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import generic.jar.ResourceFile;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;

import ghidra.framework.Application;
import ghidra.framework.options.Options;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.OperandType;
import ghidra.program.model.lang.Register;
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

public class WatcomCrtDataPropagationAnalyzer extends AbstractAnalyzer {
	private static final String NAME = "Watcom CRT Data-Touch Propagation";
	private static final String DESCRIPTION =
			"Identifies clib-internal helpers by the CRT-private DGROUP globals they reference " +
			"(heap segment header, _iob FILE table, __cstart_ argv/envp slots, ...). Functions " +
			"that touch any of those addresses get renamed `__clib_<category>_ANON_<entry>` and " +
			"bookmarked, even when FID missed them and call-graph propagation stranded them.";

	private static final String BOOKMARK_CATEGORY = "WatcomCRT";
	private static final String CATEGORIES_RESOURCE = "crt_categories.json";

	public WatcomCrtDataPropagationAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.FUNCTION_ANALYZER);

		setPriority(AnalysisPriority.FUNCTION_ID_ANALYSIS.after().after().after().after().after());
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

		Map<String, String> nameToCategory = loadCategories(log);
		if(nameToCategory.isEmpty()) {
			log.appendMsg(NAME, "no crt_categories.json available; skipping");
			return true;
		}

		FunctionManager functionManager = program.getFunctionManager();
		Listing listing = program.getListing();

		Map<Long, String> offsetToCategory = new HashMap<>();
		Map<String, Integer> categoryHitCounts = new LinkedHashMap<>();
		int seedFunctions = 0;

		for(Function function : functionManager.getFunctions(true)) {
			monitor.checkCancelled();

			String category = nameToCategory.get(function.getName());
			if(category == null) continue;

			seedFunctions++;

			for(long offset : dataOffsetsOf(function, listing)) {
				offsetToCategory.putIfAbsent(offset, category);
				categoryHitCounts.merge(category, 1, Integer::sum);
			}
		}

		log.appendMsg(
				NAME,
				"seeded " +
				seedFunctions +
				" named CRT functions; recorded " +
				offsetToCategory.size() +
				" category-private offsets (" +
				categoryHitCounts +
				")");

		if(offsetToCategory.isEmpty()) return true;

		int tagged = 0;
		Map<String, Integer> taggedByCategory = new LinkedHashMap<>();
		for(Function function : functionManager.getFunctions(true)) {
			monitor.checkCancelled();

			if(function.isThunk() || function.isExternal()) continue;
			if(function.getSymbol().getSource() != SourceType.DEFAULT) continue;
			if(WatcomCrtAnchors.USER_CODE_ANCHORS.contains(function.getName())) continue;

			String winningCategory = null;
			for(long offset : dataOffsetsOf(function, listing)) {
				String c = offsetToCategory.get(offset);
				if(c != null) {
					winningCategory = c;
					break;
				}
			}

			if(winningCategory == null) continue;

			String newName = String.format(
					"__clib_%s_ANON_%s",
					winningCategory,
					function.getEntryPoint().toString().replace(":", "_"));

			try {
				function.setName(newName, SourceType.ANALYSIS);
				markBookmarkAndPlate(program, function, winningCategory);

				tagged++;
				taggedByCategory.merge(winningCategory, 1, Integer::sum);
			}
			catch(Exception exception) {
				log.appendMsg(NAME, "rename " + function.getEntryPoint() + ": " + exception.getMessage());
			}
		}

		log.appendMsg(NAME, "tagged " + tagged + " functions: " + taggedByCategory);
		return true;
	}

	private static List<Long> dataOffsetsOf(Function function, Listing listing) {
		List<Long> out = new ArrayList<>();
		Set<Long> seen = new HashSet<>();

		InstructionIterator it = listing.getInstructions(function.getBody(), true);
		while(it.hasNext()) {
			Instruction instruction = it.next();
			for(int i = 0; i < instruction.getNumOperands(); i++) {
				int type = instruction.getOperandType(i);
				if((type & OperandType.DYNAMIC) == 0) continue;

				Object[] objects = instruction.getOpObjects(i);
				if(objects.length == 0) continue;

				boolean hasRegister = false;
				Long scalarOffset = null;

				for(Object object : objects) {
					if(object instanceof Register) { hasRegister = true; break; }
					if(object instanceof Scalar) scalarOffset = ((Scalar) object).getValue();
				}

				if(hasRegister || scalarOffset == null) continue;

				if(scalarOffset < 0x100 || scalarOffset > 0xFFFF) continue;
				if(seen.add(scalarOffset)) out.add(scalarOffset);
			}
		}
		return out;
	}

	private static void markBookmarkAndPlate(Program program, Function function, String category) {
		Address entry = function.getEntryPoint();
		String note = "likely Watcom CRT internal (touches " + category + "-private DGROUP global)";
		program.getBookmarkManager().setBookmark(entry, BookmarkType.ANALYSIS, BOOKMARK_CATEGORY, note);

		String plate = "Likely Watcom CRT internal; references " + category +
				"-private DGROUP global; user code never touches these directly.\n" +
				"Marked by Watcom CRT Data-Touch Propagation. Rename to override.";

		Listing listing = program.getListing();
		String existing = listing.getComment(CommentType.PLATE, entry);
		if(existing == null || existing.contains("Watcom CRT")) {
			listing.setComment(entry, CommentType.PLATE, plate);
		}
	}

	private static Map<String, String> loadCategories(MessageLog log) {
		ResourceFile resource;
		try {
			resource = Application.getModuleDataFile(CATEGORIES_RESOURCE);
		}
		catch(java.io.FileNotFoundException notFound) {
			return Collections.emptyMap();
		}

		Map<String, String> out = new HashMap<>();
		try(BufferedReader reader = new BufferedReader(new InputStreamReader(resource.getInputStream(), StandardCharsets.UTF_8))) {
			JsonElement root = JsonParser.parseReader(reader);
			if(!root.isJsonObject()) return out;

			JsonObject obj = root.getAsJsonObject();
			for(Map.Entry<String, JsonElement> entry : obj.entrySet()) {
				String category = entry.getKey();

				JsonElement value = entry.getValue();
				if(!value.isJsonArray()) continue;

				JsonArray array = value.getAsJsonArray();
				for(JsonElement nameElement : array) {
					if(nameElement.isJsonPrimitive()) {
						out.put(nameElement.getAsString(), category);
					}
				}
			}
		}
		catch(java.io.IOException exception) {
			log.appendMsg(NAME, "failed to read " + CATEGORIES_RESOURCE + ": " + exception.getMessage());
		}

		return out;
	}
}
