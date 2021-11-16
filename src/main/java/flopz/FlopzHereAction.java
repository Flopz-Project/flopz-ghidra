package flopz;

import docking.ActionContext;
import docking.action.MenuData;
import ghidra.app.context.ListingActionContext;
import ghidra.app.context.ListingContextAction;
import ghidra.util.Msg;

public class FlopzHereAction extends ListingContextAction {
	private FlopzPlugin plugin;
	
	public FlopzHereAction(FlopzPlugin plugin, String groupName) {
		super("Instrument here", plugin.getName());
		this.plugin = plugin;
		
		setPopupMenuData(new MenuData(new String[] {"Flopz", "Instrument Function"}, null, groupName));
	}
	
	@Override
	public void actionPerformed(ListingActionContext context) {
		this.plugin.flopzHere(context);
	}
}
