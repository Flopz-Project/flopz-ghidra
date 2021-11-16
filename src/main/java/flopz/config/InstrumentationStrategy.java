package flopz.config;

import java.util.List;

public class InstrumentationStrategy {
	public String name;
	
	// defines how many bytes are required for the instrumentation entry point (the patch slice)
	public int desired_patch_size;
	
	// flopz-ghidra will check each candidate patch slice
	// if it contains one of these blacklisted instructions, it will try to find a different instruction
	public List<String> blacklisted_mnemonics;
	
	public boolean isInstructionBlacklisted(String mnemonic) {
		for(String listed: blacklisted_mnemonics) {
			if(listed.contains(mnemonic)) {
				return true;
			}
		}
		return false;
	}
}
