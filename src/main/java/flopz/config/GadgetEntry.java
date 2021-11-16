package flopz.config;

public class GadgetEntry {
	public String strategy_name = ""; // which instrumentation strategy was used?
	
	// can have: only patch, or both patch and trace
	public TraceEntry trace;
	public PatchEntry patch;
}
