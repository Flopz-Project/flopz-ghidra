package flopz;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.stream.JsonReader;

import flopz.config.Project;
import ghidra.util.Msg;

public class FlopzConfigFile {
	private Project flopzProject;
	private String path;
	
	
	public void open(File file) {
		Gson gson = new Gson();
		try {
			JsonReader reader = new JsonReader(new FileReader(file));
			flopzProject = gson.fromJson(reader, Project.class);
		} catch (FileNotFoundException e) {
			Msg.warn(this, "Flopz Error: error operning config: file does not exist! Creating a new file instead.");
			this.flopzProject = new Project();
		}
		this.path = file.getAbsolutePath();
	}
	
	public void save() {
		 Gson gson = new GsonBuilder()
			     .setPrettyPrinting()
			     .create();
        
        try (FileWriter writer = new FileWriter(path)) {
            gson.toJson(flopzProject, writer);
        } catch (IOException e) {
            Msg.error(this, "Could not write flopz config file!");
        }
	}
	
	public void saveTo() {
		
	}
	
	public Project getProject() {
		return flopzProject;
	}
	
}
