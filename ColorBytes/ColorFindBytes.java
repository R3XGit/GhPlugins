//This script is finding the bytes
/*
 * This script is designed to find bytes in the listing. 
 * Highlighting occurs only when the address of the command
 *  and the start address of the group of bytes coincide.
 *  				Find them !
 */
//@author Rex
//@category 
//@keybinding ctrl 1
//@menupath 
//@toolbar Info.png


import java.awt.Color;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import ghidra.app.plugin.core.colorizer.ColorizingService;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.exception.CancelledException;

public class FindByte extends GhidraScript {

    public void run() throws Exception {
    	println("Start searching in " + currentProgram.getName());
    	
    	List<Address> FOUNDBYTES = Scan();
    	FOUNDBYTES.addAll(Scan());
    	
    	Map<String, Integer> ColorMap = new HashMap<String, Integer>();
    	
    	ColorMap.put("red", 0);
    	ColorMap.put("green",1);
    	ColorMap.put("yellow",2);
    	ColorMap.put("blue",3);
    	int [][] ColorByte = 
    		{{0xff,0x49,0x1b},		//red
    		{0xb9,0xff,0xab},		//green
    		{0xde,0xe5,0x19},		//yellow
    		{0x37,0xc9,0xf6}};		//blue
    	
    	String choice = askChoice("Color", "Choose one",
				new String[] { "red","green","yellow","blue"},"");
    	
    	Integer c = ColorMap.get(choice);
    	
    	for(int i=0; i<FOUNDBYTES.size(); i++) {
    		ColorizingService service = state.getTool().getService(ColorizingService.class);
    		if (service == null) {
    			println("Error: something wrong with colorizer");
    			return;
    		}
    		service.setBackgroundColor(FOUNDBYTES.get(i),FOUNDBYTES.get(i),
			new Color(ColorByte[c][0],ColorByte[c][1],ColorByte[c][2]));
    		println(FOUNDBYTES.get(i).toString());
    	}
    	
    }
    
    List<Address> Scan() throws CancelledException {
    	
    	byte[] enterBytes = askBytes("Enter your bytes", "Find them !");
		List<Address> foundAddress = scanForBytes(enterBytes);
		
		return foundAddress;
    }
	
    List<Address> scanForBytes(byte[] searchBytes) {
		Memory memory = currentProgram.getMemory();
		MemoryBlock[] blocks = memory.getBlocks();

		byte maskBytes[] = null;

		List<Address> foundAddresses = new ArrayList<Address>();

		for (int i = 0; i < blocks.length; i++) {
			if (blocks[i].isInitialized()) {
				Address start = blocks[i].getStart();
				Address found = null;
				while (true) {
					if (monitor.isCancelled()) {
						break;
					}
					found = memory.findBytes(start, blocks[i].getEnd(), searchBytes, maskBytes, true, monitor);
					if (found != null) {
						foundAddresses.add(found);
						start = found.add(1);
					}
					else
						break;
				}
			}
		}
		return foundAddresses;
	}
}
