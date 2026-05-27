// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Emily "TTG" Banerjee <prs.ttg+dedagger@pm.me>

package watcomdos;

import ghidra.app.cmd.function.DecompilerParameterIdCmd;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;

import ghidra.framework.options.Options;

import ghidra.program.model.address.AddressSetView;
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
			"For Watcom-compiled DOS programs (compilerSpecification watcom or watcom16), pin every " +
			"function's calling convention to the language default (__watcall / __watcall16). " +
			"Overrides the segmented x86 heuristic on register-call function bodies.";
	private static final String SEGMENTED_ANALYZER = "Segmented X86 Calling Conventions";
	private static final int DECOMPILER_TIMEOUT_SECONDS = 60;

	public WatcomDefaultsAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.FUNCTION_ANALYZER);

		setPriority(AnalysisPriority.FUNCTION_ID_ANALYSIS.after().after());
		setDefaultEnablement(true);
	}

	@Override
	public boolean canAnalyze(Program program) {
		String id = program.getCompilerSpec().getCompilerSpecID().getIdAsString();
		return "watcom".equals(id) || "watcom16".equals(id);
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
		CompilerSpec compilerSpecification = program.getCompilerSpec();

		Options analysisOptions = program.getOptions("Analyzers");
		if(analysisOptions.contains(SEGMENTED_ANALYZER) &&
				analysisOptions.getBoolean(SEGMENTED_ANALYZER, true)) {
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
			catch (Exception exception) {
				log.appendMsg(NAME, "failed " + function.getEntryPoint() + " " + function.getName() + ": " + exception.getMessage());
			}
		}

		log.appendMsg(NAME, "default = " + defaultName + ", reset = " + reset + ", skipped = " + skipped + ", kept(user-defined) = " + kept);

		// Stock "Decompiler Parameter ID" is off by default and toggling its option mid-analysis
		// doesn't reschedule it. Invoke the same command directly so register-call functions get
		// recovered parameters instead of decompiling as parameterless with bare in_AX/in_DL etc.
		DecompilerParameterIdCmd parameterCmd = new DecompilerParameterIdCmd(
				"Decompiler Parameter ID",
				set,
				SourceType.ANALYSIS,
				true,
				false,
				DECOMPILER_TIMEOUT_SECONDS);
		parameterCmd.applyTo(program, monitor);

		return true;
	}
}
