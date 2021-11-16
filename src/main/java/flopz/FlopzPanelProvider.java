package flopz;

import java.awt.BorderLayout;
import java.awt.GridLayout;
import java.awt.Dimension;
import java.io.File;

import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.ListSelectionModel;

import docking.ActionContext;
import docking.ComponentProvider;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.action.ToolBarData;
import docking.widgets.filechooser.GhidraFileChooser;
import docking.widgets.filechooser.GhidraFileChooserMode;
import flopz.config.GadgetEntry;
import flopz.config.Project;
import ghidra.app.context.ListingActionContext;
import ghidra.app.context.ListingContextAction;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.filechooser.ExtensionFileFilter;
import resources.Icons;

// TODO: If provider is desired, it is recommended to move it to its own file
public class FlopzPanelProvider extends ComponentProvider {

	private JPanel panel;
	private JLabel targetFlashAddrLabel;
	private JLabel targetFlashSizeLabel;
	private JLabel targetRamAddrLabel;
	private JLabel targetRamSizeLabel;
	private JLabel initPatchLocationLabel;
	
	private DockingAction action;
	// chooser for selecting a config file:
	private GhidraFileChooser chooser;
	private FlopzPlugin plugin;	
	private FlopzConfigFile config;
	private PluginTool tool;	
	
	private FlopzConfigTableModel model;
	private FlopzConfigTable table;
	
	private DockingAction openConfigAction;
	private DockingAction saveConfigAction;
	private DockingAction deleteTraceAction;

	public FlopzPanelProvider(FlopzPlugin plugin, String owner) {
		super(plugin.getTool(), "Flopz Panel", owner);
		tool = plugin.getTool();
		this.plugin = plugin;
		config = plugin.getConfig();
		buildPanel();
		createActions();
	}

	// Customize GUI
	private void buildPanel() {
		panel = new JPanel(new BorderLayout());
		
		// show target entries (ram/flash)
		JPanel targetEntryPanel = new JPanel(new GridLayout(0,4));
		
		targetFlashAddrLabel = new JLabel("/");
		targetEntryPanel.add(new JLabel("Target Flash Address:"));
		targetEntryPanel.add(targetFlashAddrLabel);

		targetFlashSizeLabel = new JLabel("/");
		targetEntryPanel.add(new JLabel("Target Flash Size:"));
		targetEntryPanel.add(targetFlashSizeLabel);
		
		
		targetRamAddrLabel = new JLabel("/");
		targetEntryPanel.add(new JLabel("Target RAM Address:"));
		targetEntryPanel.add(targetRamAddrLabel);
		
		targetRamSizeLabel = new JLabel("/");
		targetEntryPanel.add(new JLabel("Target RAM Size:"));
		targetEntryPanel.add(targetRamSizeLabel);
		
		initPatchLocationLabel = new JLabel("/");
		targetEntryPanel.add(new JLabel("Init. Patch Address:"));
		targetEntryPanel.add(initPatchLocationLabel);
		
		panel.add(targetEntryPanel, BorderLayout.NORTH);
		
		// build model, table
		model = new FlopzConfigTableModel(plugin);
		table = new FlopzConfigTable(model);
		
		table.setAutoLookupColumn(model.ADDRESS_COLUMN);		
		table.setRowSelectionAllowed(true);
		table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
		table.getSelectionModel().addListSelectionListener(e -> tool.contextChanged(this));
		table.setNavigateOnSelectionEnabled(true);
		
		var scrollPane = new JScrollPane(table);
		
		panel.add(scrollPane, BorderLayout.CENTER);
		
		
		setVisible(true);
	}

	private void createActions() {
				
		openConfigAction = new DockingAction("Set Config File", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				chooser = new GhidraFileChooser(tool.getActiveWindow());

				var filter = ExtensionFileFilter.forExtensions("Flopz Config .json", "json");
				chooser.addFileFilter(filter);
				chooser.setSelectedFileFilter(filter);

				chooser.setFileSelectionMode(GhidraFileChooserMode.FILES_ONLY);
				chooser.setMultiSelectionEnabled(false);
				chooser.setTitle("Select Report to import");
				File selected = chooser.getSelectedFile();
				if (selected != null) {
					config.open(selected);
					plugin.onConfigChange();
					saveConfigAction.setEnabled(true);
					updatePanel();
				}
			}
		};
		openConfigAction.setToolBarData(new ToolBarData(Icons.OPEN_FOLDER_ICON, null));
		openConfigAction.setEnabled(true);
		openConfigAction.markHelpUnnecessary();
		dockingTool.addLocalAction(this, openConfigAction);
				
		saveConfigAction = new DockingAction("Save Config File", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				try { 
					config.save();
					Msg.showInfo(this, panel, "Flopz", "Config saved successfully!");
					
				} catch(Exception e) {
					
				}
				
			}
		};
		saveConfigAction.setToolBarData(new ToolBarData(Icons.SAVE_AS, null));
		saveConfigAction.setEnabled(false);
		saveConfigAction.markHelpUnnecessary();
		dockingTool.addLocalAction(this, saveConfigAction);
		
		deleteTraceAction = new DockingAction("Delete Selected Trace/Gadget", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				// get selected table index
				int selIdx = table.getSelectedRow();
				Project project = config.getProject();
				if(project != null && selIdx >= 0 && selIdx < project.gadgets.size()) {
					// remove comment, if it exists
					Object value = model.getValueAt(selIdx, FlopzConfigTableModel.ADDRESS_COLUMN);
					if(value != null) {
						Address address = (Address) value;
						Program program  = plugin.getCurrentProgram();
						FlatProgramAPI api = new FlatProgramAPI(program);
						String preComment = api.getPreComment(address);
						if(preComment != null && preComment.contains("FLOPZ:")) {
							api.start();
							api.setPreComment(address, "");
							api.end(true);							
						}
					}
					
					// remove from model
					for(GadgetEntry ge: config.getProject().gadgets) {
						int index = model.getModelIndex(ge);
						if(index == selIdx) {
							config.getProject().gadgets.remove(ge);
							break;
						}
					}
					table.clearSelection();
					model.reload();
					
				}
			}
		};
		deleteTraceAction.setToolBarData(new ToolBarData(Icons.DELETE_ICON, null));
		deleteTraceAction.setEnabled(true);
		deleteTraceAction.markHelpUnnecessary();
		dockingTool.addLocalAction(this, deleteTraceAction);
		

		action = new SetTargetFlashAction(this.plugin, "Flopz");
		dockingTool.addAction(action);
		action = new SetTargetRamAction(this.plugin, "Flopz");
		dockingTool.addAction(action);
		action = new SetInitPatchAction(this.plugin, "Flopz");
		dockingTool.addAction(action);		
		action = new FlopzHereAction(this.plugin, "Flopz");
		dockingTool.addAction(action);
		action = new FlopzAllSelectedAction(this.plugin, "Flopz");
		dockingTool.addAction(action);

	}	
	
	public void updatePanel() {
		// get project, update table
		Project flopzProject =  plugin.getConfig().getProject();
		if(flopzProject != null) {
			// populate target* labels
			targetFlashAddrLabel.setText(flopzProject.target_flash.start_addr);
			targetFlashSizeLabel.setText(flopzProject.target_flash.size);
			targetRamAddrLabel.setText(flopzProject.target_ram.start_addr);
			targetRamSizeLabel.setText(flopzProject.target_ram.size);
			initPatchLocationLabel.setText(flopzProject.init_patch_location.addr);
			
			
			// populate model
			model.setProgram(plugin.getCurrentProgram());
			table.installNavigation(plugin.getGoToService(), plugin.getGoToService().getDefaultNavigatable());
			model.reload();
		}
	}

	@Override
	public JComponent getComponent() {
		return panel;
	}
}