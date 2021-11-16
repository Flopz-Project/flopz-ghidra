package flopz;

import docking.action.MenuData;
import ghidra.app.context.ListingActionContext;
import ghidra.app.context.ListingContextAction;

public class FlopzAllSelectedAction extends ListingContextAction {
	private FlopzPlugin plugin;
	
	public FlopzAllSelectedAction(FlopzPlugin plugin, String groupName) {
		super("Instrument Selected", plugin.getName());
		this.plugin = plugin;
		
		setPopupMenuData(new MenuData(new String[] { "Flopz", "Instrument Selected Functions" }, null, groupName));
	}
	
	@Override
	public void actionPerformed(ListingActionContext context) {
		this.plugin.flopzAllSelected(context);
	}
}
