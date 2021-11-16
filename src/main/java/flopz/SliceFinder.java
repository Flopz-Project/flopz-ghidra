package flopz;

import flopz.config.DumpEntry;
import flopz.config.GadgetEntry;
import flopz.config.InstrumentationConfiguration;
import flopz.config.InstrumentationStrategy;
import flopz.config.PatchEntry;
import flopz.config.Project;
import flopz.config.TraceEntry;
import ghidra.app.plugin.core.format.HexFormatModel;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressRangeIterator;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.CodeUnitIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.util.CommentType;
import ghidra.util.Msg;
import ghidra.util.NumericUtilities;
import ghidra.util.task.TaskMonitor;


public class SliceFinder {
	// it finds slices!
	private InstrumentationConfiguration instrumentationConfig;
	private Project project;
	
	public SliceFinder(InstrumentationConfiguration c, Project p) {
		instrumentationConfig = c;
		project = p;
	}
	
	
	/*
	 * This will instrument the function that contains "address"
	 */
	public void instrumentSingleFunction(Program program, Address address) {
		try {
			InstrumentationStrategy strategy = getDefaultStrategy();
			
			// find suitable instruction
			Listing listing = program.getListing();
			FunctionManager funcManager = program.getFunctionManager();
			Function func = funcManager.getFunctionContaining(address);
			if(func == null) {
				Msg.error(this, "No function found.");
				Msg.showWarn(this, null, "Flopz", "Could not instrument here!");
				return;
			}
			
			// check if already instrumented
			for(GadgetEntry e: project.gadgets) {
				if(e.strategy_name.isEmpty() || e.strategy_name.equals(strategy.name)) {
					Address alreadyInstrumentedAddress = program.getAddressFactory().getAddress(e.patch.addr);
					if(funcManager.getFunctionContaining(alreadyInstrumentedAddress).getEntryPoint().equals(func.getEntryPoint())) {
						Msg.warn(this, "Function already instrumented! Skipping.");
						return;
					}
				}
			}
			
			AddressSetView addrSet = func.getBody();
			CodeUnitIterator codeUnits = listing.getCodeUnits(addrSet, true); //forward = true

			CodeUnit targetInstruction = null;
			for(CodeUnit instruction: codeUnits) {
				var mnemonicStr = instruction.getMnemonicString();
				if(strategy.isInstructionBlacklisted(mnemonicStr)) {
					continue;
				}
				
				// check length and instrument, if the next instruction is not blacklisted either
				var bytes = instruction.getBytes();
				if(bytes.length == strategy.desired_patch_size) {
					if(codeUnits.hasNext()) {
						var next_ins = codeUnits.next();
						var next_mnemonic = next_ins.getMnemonicString();
						if(strategy.isInstructionBlacklisted(next_mnemonic)) {
							continue; // skip
						}
					}
					// take it!
					targetInstruction = instruction;
					break;
				}
			}
			
			
			if(targetInstruction != null) {
				FlatProgramAPI api = new FlatProgramAPI(program);
				// make a comment
				api.start();
				api.setPreComment(targetInstruction.getAddress(), "FLOPZ: Target Instruction for Function Trace");
				api.end(true);
				
				// add to FlopzConfig
				var bytes = targetInstruction.getBytes();
				GadgetEntry entry = new GadgetEntry();
				entry.strategy_name = strategy.name;
				entry.patch = new PatchEntry();
				entry.patch.addr = "0x" + targetInstruction.getAddressString(false, false); 
				entry.patch.original_mnemonics = targetInstruction.getMnemonicString();
				entry.patch.original_bytes = NumericUtilities.convertBytesToString(bytes);
				entry.trace = new TraceEntry();
				entry.trace.level = "function";
				entry.trace.id = project.getHighestTraceId() + 1;
				var dumpEntry = new DumpEntry();
				dumpEntry.type = "id";
				entry.trace.dump.add(dumpEntry);

				// add to project/config
				project.gadgets.add(entry);
				project.setHasChanged(true);
			} else {
				Msg.showWarn(this, null, "Flopz", "Could not instrument here!");
			}
			
			
		} catch(SliceFinderException e) {
			Msg.error(this, "instrumentSingleFunction failed! Aborting.");
			return;
		} catch(MemoryAccessException e) {
			Msg.error(this, "instrumentSingleFunction failed: error accessing instruction memory. Aborting.");
			return;			
		}
		
	}
	
	/*
	 * this will instrument all functions containing addresses from "selection"
	 */
	public void instrumentSelectedFunctions(Program program, AddressSetView selection) {
		Listing listing = program.getListing();
		FunctionManager funcManager = program.getFunctionManager();
		
		FunctionIterator funcIt = funcManager.getFunctions(selection, true);
		
		// get all selected functions
		for(Function f: funcIt) {
			instrumentSingleFunction(program, f.getEntryPoint());
		}
	}
	
	/*
	 * instrument all basic blocks in function containing "address"
	 */
	public void instrumentFunctionBasicBlocks(Program program, Address address) {
		
	}
	
	private InstrumentationStrategy getDefaultStrategy() throws SliceFinderException {
		// do we have strategies configured?
		if(instrumentationConfig.strategies.size() < 1) {
			Msg.error(this, "No InstrumentationStrategies defined in InstrumentationConfiguration! Aborting.");
			throw new SliceFinderException("No InstrumentationStrategies defined in InstrumentationConfiguration! Aborting.");
		}
		// select default strategy: it's the first one that appears in the list
		InstrumentationStrategy strategy = instrumentationConfig.strategies.get(0);
		return strategy;
	}

}
