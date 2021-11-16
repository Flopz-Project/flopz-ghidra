package flopz.config;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class Project {
	public String project; // project name
	public String binary; // binary name
	public float schema_version;
	
	// let's see if we can parse it like this
	public TargetEntry target_flash;
	public TargetEntry target_ram;
	
	public PatchEntry init_patch_location;
	
	public List<GadgetEntry> gadgets;
	
	private boolean hasChanged = false;
	
	public Project() {
		// initialize empty fields
		project = "";
		binary = "";
		schema_version = 1.0f;
		target_flash = new TargetEntry();
		target_ram = new TargetEntry();
		init_patch_location = new PatchEntry();
		gadgets = new ArrayList<GadgetEntry>();
	}
	
	public boolean getHasChanged() {
		return hasChanged;
	}
	
	public void setHasChanged(boolean b) {
		hasChanged = b;
	}
	
	/*
	 * returns the highest ID found in the config
	 */
	public int getHighestTraceId() {
		int lastId = 0;
		for(GadgetEntry e: gadgets) {
			if(e.trace != null && e.trace.id != 0) {
				if(e.trace.id > lastId) {
					lastId = e.trace.id;
				}
			}
		}
		return lastId;
	}
}
