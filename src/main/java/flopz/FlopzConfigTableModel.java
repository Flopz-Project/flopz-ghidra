package flopz;

import docking.widgets.table.TableColumnDescriptor;
import flopz.config.GadgetEntry;
import ghidra.docking.settings.Settings;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Program;
import ghidra.program.util.AddressFieldLocation;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;
import ghidra.util.datastruct.Accumulator;
import ghidra.util.exception.CancelledException;
import ghidra.util.table.AddressBasedTableModel;
import ghidra.util.table.field.AbstractProgramBasedDynamicTableColumn;
import ghidra.util.table.field.ProgramLocationTableColumnExtensionPoint;
import ghidra.util.task.TaskMonitor;

public class FlopzConfigTableModel extends AddressBasedTableModel<GadgetEntry> {
	private FlopzConfigFile config;
	private FlopzPlugin plugin;
	
	public final static int ADDRESS_COLUMN = 0;
	
	public FlopzConfigTableModel(FlopzPlugin p) {
		super("Instrumented Locations", p.getTool(), null, null);
		plugin = p;
		config = plugin.getConfig();
	}

	@Override
	public Address getAddress(int row) {
		return (Address) this.getColumnValueForRow(this.getRowObject(row), ADDRESS_COLUMN);
	}
	
	@Override
	protected TableColumnDescriptor<GadgetEntry> createTableColumnDescriptor() {
		TableColumnDescriptor<GadgetEntry> descriptor = new TableColumnDescriptor<GadgetEntry>();

		descriptor.addVisibleColumn(new GadgetEntryAddressTableColumn(), 1, true);
		descriptor.addVisibleColumn(new GadgetTypeTableColumn());

		return descriptor;
	}	
	
	public static class GadgetEntryAddressTableColumn extends ProgramLocationTableColumnExtensionPoint<GadgetEntry, Address> {
				
		@Override
		public String getColumnName() {
			return "Address";
		}

		@Override
		public Address getValue(GadgetEntry entry, Settings settings, Program prog, ServiceProvider serviceProvider)
				throws IllegalArgumentException {
			if (prog != null && entry.patch != null && entry.patch.addr != null) {
				return prog.getAddressFactory().getAddress(entry.patch.addr);
			}
			return null;
		}

		@Override
		public ProgramLocation getProgramLocation(GadgetEntry entry, Settings settings, Program prog,
				ServiceProvider serviceProvider) {
			if (prog != null && entry.patch != null && entry.patch.addr != null) {
				return new AddressFieldLocation(prog, prog.getAddressFactory().getAddress(entry.patch.addr));
			}
			return null;

		}
	}
	
	public static class GadgetTypeTableColumn extends AbstractProgramBasedDynamicTableColumn<GadgetEntry, String> {		
		@Override
		public String getColumnName() {
			return "Type";
		}

		@Override
		public String getValue(GadgetEntry entry, Settings settings, Program data, ServiceProvider serviceProvider)
				throws IllegalArgumentException {
			return entry.trace.level;
		}
	}

	@Override
	public ProgramSelection getProgramSelection(int[] rows) {
		AddressSet newSet = new AddressSet();
		
		for(int entryIdx: rows) {			
			GadgetEntry entry = getRowObject(entryIdx);
			Object value = getColumnValueForRow(entry, ADDRESS_COLUMN);
			if (value == null)
				return null;
				
			Address address = (Address) value;
			newSet.add(address);			
		}		
		
		return new ProgramSelection(newSet);
	}

	@Override
	protected void doLoad(Accumulator<GadgetEntry> accumulator, TaskMonitor monitor) throws CancelledException {

		config = plugin.getConfig();
		if(config == null || config.getProject() == null || config.getProject().gadgets == null) {
			return;
		}
		
		accumulator.addAll(config.getProject().gadgets);
		
	}
	
}
