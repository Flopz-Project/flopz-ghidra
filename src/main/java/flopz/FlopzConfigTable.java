package flopz;

import ghidra.app.nav.Navigatable;
import ghidra.app.services.GoToService;
import ghidra.program.util.ProgramSelection;
import ghidra.util.table.GhidraTable;

public class FlopzConfigTable extends GhidraTable {
	protected Navigatable navigatable;

	public FlopzConfigTable(FlopzConfigTableModel model) {
		super(model);
	}

	@Override
	public void installNavigation(GoToService goToService, Navigatable nav) {
		super.installNavigation(goToService, nav);
		navigatable = nav;
	}

	@Override
	public void navigate(int row, int column) {
		super.navigate(row, column);
		if (navigatable == null || row < 0 || column < 0 || !(dataModel instanceof FlopzConfigTableModel)) {
			return;
		}

		column = convertColumnIndexToModel(column);

		FlopzConfigTableModel model = (FlopzConfigTableModel) dataModel;
		ProgramSelection selection = model.getProgramSelection(new int[] { row });
		if (selection.getMinAddress() != null && selection.getMinAddress().isMemoryAddress()) {
			navigatable.setSelection(selection);
		}
	}

	@Override
	public void removeNavigation() {
		super.removeNavigation();
		navigatable = null;
	}
}
