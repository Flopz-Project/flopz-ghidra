/* ###
 * IP: Noelscher Consulting GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package flopz;

import ghidra.app.CorePluginPackage;

import java.awt.BorderLayout;
import java.io.FileNotFoundException;
import java.io.FileReader;

import javax.swing.*;

import com.google.gson.Gson;
import com.google.gson.stream.JsonReader;

import docking.ActionContext;
import docking.ComponentProvider;
import docking.action.DockingAction;
import docking.action.ToolBarData;
import ghidra.app.ExamplesPluginPackage;
import ghidra.app.context.ListingActionContext;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.services.GoToService;
import ghidra.framework.Application;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.lang.Language;
import ghidra.program.model.listing.Program;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import resources.Icons;

import flopz.FlopzPanelProvider;
import flopz.config.InstrumentationConfiguration;
import flopz.config.Project;
import generic.jar.ResourceFile;

//@formatter:off
@PluginInfo(
	status = PluginStatus.STABLE,
	packageName = CorePluginPackage.NAME,
	category = PluginCategoryNames.MISC,
	shortDescription = "Ghidra plugin for Flopz: ",
	description = "This plugin generates and manages flopz configuration files that are"
			+ " used to instrument or patch binaries using the flopz python project."
)
//@formatter:on
public class FlopzPlugin extends ProgramPlugin {

	private FlopzPanelProvider panelProvider;
	private GoToService goToService;

	private FlopzConfigFile config;
	
	/**
	 * Plugin constructor.
	 * 
	 * @param tool The plugin tool that this plugin is added to.
	 */
	public FlopzPlugin(PluginTool tool) {
		super(tool, true, true);

		String pluginName = getName();
		
		config = new FlopzConfigFile();
		panelProvider = new FlopzPanelProvider(this, pluginName);

		String topicName = this.getClass().getPackage().getName();
		String anchorName = "FlopzHelpAnchor";
		panelProvider.setHelpLocation(new HelpLocation(topicName, anchorName));
		
	}

	@Override
	public void init() {
		super.init();
		// acquire services
		goToService = getTool().getService(GoToService.class);
		if(goToService == null) {
			Msg.warn(this, "Flopz Error: can't get GoToService! Navigation won't work!");
		}
	}	

	public void onConfigChange() {
		// synchronize config fields if they're not set
		Project project = config.getProject();
		if(project != null) {
			if(project.project.length() < 1) {
				// TODO: set project name				
			}
			if(project.binary.length() < 1) {
				// set binary name
				project.binary = currentProgram.getName();				
			}
		}
	}
	
	public void updateData() {
		panelProvider.updatePanel();
	}
	
	// exposed internal methods
	public void setConfig(FlopzConfigFile cfg) {
		config = cfg;
	}
	
	public FlopzConfigFile getConfig() {
		return config;
	}
	
	public GoToService getGoToService() {
		return goToService;
	}
	
	public void flopzHere(ListingActionContext context) {
		// check if we have a project
		if(config.getProject() == null) {
			Msg.showError(this, null, "Flopz", "Can't instrument: Please load a project first!");
			return;
		}
		
		InstrumentationConfiguration insConfig = getInstrumentationConfig(context);
		if(insConfig == null)
			return;
		
		SliceFinder sf = new SliceFinder(insConfig, config.getProject());
		sf.instrumentSingleFunction(getCurrentProgram(), context.getAddress());
		
		// now, we need to run our instrumenter, passing: the insConfig, the current project
		// after that, the project should be updated in-place, so the table should be updated too!		
		if(config.getProject().getHasChanged()) {
			panelProvider.updatePanel();
			config.getProject().setHasChanged(false);
		}		
	}
	
	public void flopzAllSelected(ListingActionContext context) {
		// check if we have a project
		if(config.getProject() == null) {
			Msg.showError(this, null, "Flopz", "Can't instrument: Please load a project first!");
			return;
		}
		
		InstrumentationConfiguration insConfig = getInstrumentationConfig(context);
		if(insConfig == null)
			return;
		
		SliceFinder sf = new SliceFinder(insConfig, config.getProject());
		sf.instrumentSelectedFunctions(getCurrentProgram(), context.getSelection());
		
		// now, we need to run our instrumenter, passing: the insConfig, the current project
		// after that, the project should be updated in-place, so the table should be updated too!		
		if(config.getProject().getHasChanged()) {
			panelProvider.updatePanel();
			config.getProject().setHasChanged(false);
		}	
	}
	
	private InstrumentationConfiguration getInstrumentationConfig(ListingActionContext context) {
		try {
			Language lang = context.getProgram().getLanguage();
			ResourceFile icFile = Application.getModuleDataFile("Flopz", "instrumentation/" + lang.getLanguageID().toString() + "/instrumentation_config.json");
			
			Gson gson = new Gson();
			JsonReader reader = new JsonReader(new FileReader(icFile.getAbsolutePath()));
			return gson.fromJson(reader, InstrumentationConfiguration.class);
		} catch(FileNotFoundException e) {
			Msg.showError(this, null, "Error", "Could not find instrumentation_config.json for this processor/language! Did you copy/create it correctly?");
			return null;
		}
	}
}
