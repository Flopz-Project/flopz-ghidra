package flopz;

import javax.swing.Icon;

import docking.ActionContext;
import docking.action.MenuData;
import docking.widgets.OptionDialog;
import flopz.config.PatchEntry;
import flopz.config.Project;
import ghidra.app.context.ListingActionContext;
import ghidra.app.context.ListingContextAction;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.Msg;
import ghidra.util.NumericUtilities;

public class SetInitPatchAction extends ListingContextAction {
	private FlopzPlugin plugin;
	
	public SetInitPatchAction(FlopzPlugin plugin, String groupName) {
		super("Define Init. Patch Here", plugin.getName());
		this.plugin = plugin;
		
		setPopupMenuData(new MenuData(new String[] {"Flopz", "Define Init. Patch Here"}, null, groupName));
	}
	
	@Override
	public void actionPerformed(ListingActionContext context) {
		var project = plugin.getConfig().getProject();
		if(project == null) {
			return;
		}
		
		// see if this is an instruction
		Address addr = context.getAddress();
		
		Listing listing = context.getProgram().getListing();
		Instruction ins = listing.getInstructionAt(addr);
		if(ins != null) {
			try {
				project.init_patch_location = new PatchEntry();
				project.init_patch_location.addr = "0x" + context.getAddress().toString();
				
				project.init_patch_location.original_bytes =  NumericUtilities.convertBytesToString(ins.getBytes());
				project.init_patch_location.original_mnemonics = ins.getMnemonicString();
	
				plugin.updateData();			
			} catch(MemoryAccessException e) {
				Msg.showError(this, null, "Could not read instruction memory! Aborting.", e);
				return;
			}
		}
		
			
	}
}
