package flopz.config;

public class TargetEntry {
	public String start_addr;
	public String size;
	
	public int getStartAddr() {
		return Integer.parseInt(start_addr, 16);		
	}
	
	public int getSize() {
		return Integer.parseInt(size, 16);
	}
}
