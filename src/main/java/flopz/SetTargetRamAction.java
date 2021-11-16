package flopz;

import javax.swing.Icon;

import docking.ActionContext;
import docking.action.MenuData;
import docking.widgets.OptionDialog;
import flopz.config.Project;
import ghidra.app.context.ListingActionContext;
import ghidra.app.context.ListingContextAction;
import ghidra.util.Msg;

public class SetTargetRamAction extends ListingContextAction {
	private FlopzPlugin plugin;
	
	public SetTargetRamAction(FlopzPlugin plugin, String groupName) {
		super("Define Target RAM Here", plugin.getName());
		this.plugin = plugin;
		
		setPopupMenuData(new MenuData(new String[] {"Flopz", "Define Target RAM Here"}, null, groupName));
	}
	
	@Override
	public void actionPerformed(ListingActionContext context) {
		var project = plugin.getConfig().getProject();
		if(project == null) {
			return;
		}
		
		// ask for a size
		String sizeStr = OptionDialog.showInputSingleLineDialog(null, "Flopz", "Please Enter the Target RAM Size in hex (prefix 0x):", "0x10");
		if(sizeStr == null || sizeStr.length() < 1) {
			Msg.showError(this, null, "Flopz", "Could not read size! Aborting!");
			return;
		} 		
		
		project.target_ram.start_addr = "0x" + context.getAddress().toString();
		project.target_ram.size = sizeStr;
		plugin.updateData();		
	}
}
