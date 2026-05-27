// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Emily "TTG" Banerjee <prs.ttg+dedagger@pm.me>

package watcomdos;

import java.io.File;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import generic.jar.ResourceFile;

import ghidra.app.cmd.function.ApplyFunctionSignatureCmd;
import ghidra.app.cmd.function.DecompilerParameterIdCmd;
import ghidra.app.cmd.function.FunctionRenameOption;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;

import ghidra.feature.fid.db.FidQueryService;
import ghidra.feature.fid.db.LibraryRecord;
import ghidra.feature.fid.service.FidMatch;
import ghidra.feature.fid.service.FidSearchResult;
import ghidra.feature.fid.service.FidService;

import ghidra.framework.Application;
import ghidra.framework.options.Options;

import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.Category;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.FileDataTypeManager;
import ghidra.program.model.data.FunctionDefinition;
import ghidra.program.model.lang.CompilerSpec;
import ghidra.program.model.lang.PrototypeModel;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;

import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class WatcomDefaultsAnalyzer extends AbstractAnalyzer {
	private static final String NAME = "Watcom Calling Convention Defaults";
	private static final String DESCRIPTION =
			"For Watcom-compiled DOS programs (compilerSpecification watcom, watcom16, or watcom16far): " +
			"pin every function's calling convention to the language default (__watcall / __watcall16) and " +
			"apply C library type info from the matching memory-model GDT (small/medium/compact/large/huge/flat). " +
			"The memory model is auto-detected by tallying FID match variants; override via the analyzer option.";

	private static final String SEGMENTED_ANALYZER = "Segmented X86 Calling Conventions";
	private static final int DECOMPILER_TIMEOUT_SECONDS = 60;

	private static final String MODEL_OPTION = "Memory model";
	private static final String MODEL_AUTO = "auto";

	private static final String CSPEC_16_NEAR = "watcom16";
	private static final String CSPEC_16_FAR = "watcom16far";
	private static final String CSPEC_32 = "watcom";

	private static final Map<String, String> VARIANT_TO_MODEL = new HashMap<>();
	static {
		VARIANT_TO_MODEL.put("Real Mode (small)", "small");
		VARIANT_TO_MODEL.put("Real Mode (medium)", "medium");
		VARIANT_TO_MODEL.put("Real Mode (medium, opt-size)", "medium");
		VARIANT_TO_MODEL.put("Real Mode (compact)", "compact");
		VARIANT_TO_MODEL.put("Real Mode (large)", "large");
		VARIANT_TO_MODEL.put("Real Mode (large, opt-size)", "large");
		VARIANT_TO_MODEL.put("Real Mode (huge)", "huge");
		VARIANT_TO_MODEL.put("Flat 32 (register call)", "flat");
		VARIANT_TO_MODEL.put("Flat 32 (stack call)", "flat");
	}

	private static final Map<String, List<String>> CSPEC_TO_MODELS = new HashMap<>();
	static {
		CSPEC_TO_MODELS.put(CSPEC_16_NEAR, Arrays.asList("small", "medium"));
		CSPEC_TO_MODELS.put(CSPEC_16_FAR, Arrays.asList("large", "compact", "huge"));
		CSPEC_TO_MODELS.put(CSPEC_32, Arrays.asList("flat"));
	}

	public WatcomDefaultsAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.FUNCTION_ANALYZER);

		setPriority(AnalysisPriority.FUNCTION_ID_ANALYSIS.after().after());
		setDefaultEnablement(true);
	}

	@Override
	public boolean canAnalyze(Program program) {
		String id = program.getCompilerSpec().getCompilerSpecID().getIdAsString();
		return CSPEC_TO_MODELS.containsKey(id);
	}

	@Override
	public void registerOptions(Options options, Program program) {
		options.registerOption(MODEL_OPTION, MODEL_AUTO, null,
				"Memory model for type-info application. 'auto' tallies FID variant matches and picks the " +
				"dominant model compatible with the program's compiler spec. Override with a specific model " +
				"(small/medium/compact/large/huge/flat) to force a particular GDT.");
	}

	@Override
	public boolean added(
			Program program,
			AddressSetView set,
			TaskMonitor monitor,
			MessageLog log) throws CancelledException {

		FunctionManager functionManager = program.getFunctionManager();
		CompilerSpec compilerSpecification = program.getCompilerSpec();
		String compilerSpecificationId = compilerSpecification.getCompilerSpecID().getIdAsString();

		Options analysisOptions = program.getOptions("Analyzers");
		if(analysisOptions.contains(SEGMENTED_ANALYZER) && analysisOptions.getBoolean(SEGMENTED_ANALYZER, true)) {
			analysisOptions.setBoolean(SEGMENTED_ANALYZER, false);
			log.appendMsg(NAME, "disabled analyzer: " + SEGMENTED_ANALYZER);
		}

		PrototypeModel defaultPrototype = compilerSpecification.getDefaultCallingConvention();
		if(defaultPrototype == null) {
			log.appendMsg(NAME, "no default prototype model on cspec " + compilerSpecification.getCompilerSpecID());
			return false;
		}

		String defaultName = defaultPrototype.getName();

		int reset = 0;
		int kept = 0;
		int skipped = 0;
		for(Function function : functionManager.getFunctions(true)) {
			monitor.checkCancelled();

			String current = function.getCallingConventionName();
			if(defaultName.equals(current)) {
				skipped++;
				continue;
			}

			if(function.getSignatureSource() == SourceType.USER_DEFINED) {
				kept++;
				continue;
			}

			try {
				function.updateFunction(
						defaultName,
						function.getReturn(),
						java.util.Arrays.asList(function.getParameters()),
						FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS,
						true,
						SourceType.ANALYSIS);

				reset++;
			}
			catch(Exception exception) {
				log.appendMsg(NAME, "failed " + function.getEntryPoint() + " " + function.getName() + ": " + exception.getMessage());
			}
		}

		log.appendMsg(NAME, "default = " + defaultName + ", reset = " + reset + ", skipped = " + skipped + ", kept(user-defined) = " + kept);

		DecompilerParameterIdCmd parameterCmd = new DecompilerParameterIdCmd(
				"Decompiler Parameter ID",
				set,
				SourceType.ANALYSIS,
				true,
				false,
				DECOMPILER_TIMEOUT_SECONDS);

		parameterCmd.applyTo(program, monitor);

		applyTypeInfo(program, set, compilerSpecificationId, monitor, log);

		return true;
	}

	private void applyTypeInfo(
			Program program,
			AddressSetView set,
			String compilerSpecificationId,
			TaskMonitor monitor,
			MessageLog log) throws CancelledException {

		Options selfOptions = program.getOptions("Analyzers." + getName());
		String configured = selfOptions.getString(MODEL_OPTION, MODEL_AUTO);
		List<String> candidates = CSPEC_TO_MODELS.get(compilerSpecificationId);
		String model;

		if(!MODEL_AUTO.equals(configured)) {
			if(!candidates.contains(configured)) {
				log.appendMsg(
						NAME,
						"configured model '" +
						configured +
						"' is not compatible with cspec '" +
						compilerSpecificationId +
						"'; expected one of " +
						candidates +
						" or 'auto'");

				return;
			}

			model = configured;
			log.appendMsg(NAME, "model = " + model + " (configured)");
		}
		else {
			model = detectModel(program, candidates, monitor, log);
		}

		String gdtName = gdtFilename(model);
		if(gdtName == null) {
			log.appendMsg(NAME, "no GDT mapping for model '" + model + "'");
			return;
		}

		ResourceFile gdtResource;
		try {
			gdtResource = Application.getModuleDataFile("typeinfo/" + gdtName);
		}
		catch(java.io.FileNotFoundException notFound) {
			log.appendMsg(NAME, "GDT not found in module data: typeinfo/" + gdtName);
			return;
		}

		File gdtFile = gdtResource.getFile(true);
		FileDataTypeManager dtMgr;
		try {
			dtMgr = FileDataTypeManager.openFileArchive(gdtFile, false);
		}
		catch(java.io.IOException openError) {
			log.appendMsg(NAME, "failed to open " + gdtName + ": " + openError.getMessage());
			return;
		}

		try {
			Map<String, FunctionDefinition> defsByName = new HashMap<>();
			collectFunctionDefinitions(dtMgr.getRootCategory(), defsByName, monitor);

			int applied = 0;
			int unmatched = 0;
			int failed = 0;
			FunctionManager functionManager = program.getFunctionManager();
			for(Function function : functionManager.getFunctions(set, true)) {
				monitor.checkCancelled();

				FunctionDefinition def = lookupDefinition(defsByName, function.getName());
				if(def == null) {
					unmatched++;
					continue;
				}

				ApplyFunctionSignatureCmd signatureCmd = new ApplyFunctionSignatureCmd(
						function.getEntryPoint(),
						def,
						SourceType.IMPORTED,
						true,
						FunctionRenameOption.NO_CHANGE);

				if(signatureCmd.applyTo(program, monitor)) {
					applied++;
				}
				else {
					failed++;
				}
			}

			log.appendMsg(
					NAME,
					"signatures from " + gdtName +
					": applied = " + applied +
					", unmatched = " + unmatched +
					", failed = " + failed);
		}
		finally {
			dtMgr.close();
		}
	}

	private static void collectFunctionDefinitions(
			Category category,
			Map<String, FunctionDefinition> out,
			TaskMonitor monitor) throws CancelledException {

		for(DataType dataType : category.getDataTypes()) {
			if(dataType instanceof FunctionDefinition) {
				out.put(dataType.getName(), (FunctionDefinition) dataType);
			}
		}

		for(Category sub : category.getCategories()) {
			monitor.checkCancelled();
			collectFunctionDefinitions(sub, out, monitor);
		}
	}

	private static FunctionDefinition lookupDefinition(Map<String, FunctionDefinition> defs, String name) {
		FunctionDefinition def = defs.get(name);
		if(def != null) return def;

		if(name.length() > 1 && name.endsWith("_")) {
			return defs.get(name.substring(0, name.length() - 1));
		}

		return null;
	}

	private String detectModel(
			Program program,
			List<String> candidates,
			TaskMonitor monitor,
			MessageLog log) throws CancelledException {

		Map<String, Integer> votes = new LinkedHashMap<>();
		for(String candidate : candidates) votes.put(candidate, 0);

		FidService service = new FidService();
		try(FidQueryService query = service.openFidQueryService(program.getLanguage(), false)) {
			List<FidSearchResult> results = service.processProgram(
					program,
					query,
					service.getDefaultScoreThreshold(),
					monitor);

			int tallied = 0;
			for(FidSearchResult result : results) {
				if(result.matches == null || result.matches.isEmpty()) continue;

				if(result.matches.size() > 8) continue;

				for(FidMatch match : result.matches) {
					LibraryRecord library = match.getLibraryRecord();
					if(library == null) continue;

					String model = VARIANT_TO_MODEL.get(library.getLibraryVariant());
					if(model == null || !votes.containsKey(model)) continue;

					votes.merge(model, 1, Integer::sum);
					tallied++;
				}
			}

			if(tallied == 0) {
				String fallback = candidates.get(0);

				log.appendMsg(
						NAME,
						"model = " +
						fallback +
						" (auto: no FID matches; fell back to default for " +
						program.getCompilerSpec().getCompilerSpecID() +
						")");

				return fallback;
			}

			String winner = Collections.max(votes.entrySet(), Map.Entry.comparingByValue()).getKey();
			log.appendMsg(NAME, "model = " + winner + " (auto: votes " + votes + ")");

			return winner;
		}
		catch(java.io.IOException ioe) {
			String fallback = candidates.get(0);
			log.appendMsg(NAME, "model = " + fallback + " (auto: FID query failed: " + ioe.getMessage() + ")");
			return fallback;
		}
		catch(ghidra.util.exception.VersionException versionError) {
			String fallback = candidates.get(0);
			log.appendMsg(NAME, "model = " + fallback + " (auto: FID version mismatch: " + versionError.getMessage() + ")");
			return fallback;
		}
	}

	private static String gdtFilename(String model) {
		switch(model) {
			case "small": return "watcom16-small.gdt";
			case "medium": return "watcom16-medium.gdt";
			case "compact": return "watcom16-compact.gdt";
			case "large": return "watcom16-large.gdt";
			case "huge": return "watcom16-huge.gdt";
			case "flat": return "watcom32-flat.gdt";
			default: return null;
		}
	}
}
