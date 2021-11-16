package flopz.config;

public class PatchEntry {
	public String addr;
	public String original_bytes;
	public String original_mnemonics;
	// optional:
	public String value;
	
	public int getAddr() {
		return Integer.parseInt(addr, 16);
	}
}
