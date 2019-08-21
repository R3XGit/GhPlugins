////////////////////////////////////////////
//										  //
//		   This plugin is designed        //
//       to find vulnerable functions     //
//										  //
////////////////////////////////////////////
//@author Rex
//@category -
//@keybinding ctrl 1
//@menupath 
//@toolbar Info.png

import ghidra.app.script.GhidraScript;
import ghidra.program.model.symbol.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import java.awt.Color;
import java.util.ArrayList;
import ghidra.program.model.symbol.Reference;
import ghidra.app.plugin.core.colorizer.ColorizingService;

public class ColorFunctions extends GhidraScript {

	public void run() {
        SymbolTable st = state.getCurrentProgram().getSymbolTable();
        SymbolIterator iter = st.getSymbolIterator(true);
        
    	ArrayList<String> FindIns = new ArrayList<>();
    	FindIns.add("puts");
    	FindIns.add("gets");
    	FindIns.add("scanf");
    	FindIns.add("printf");
    	
    	String StrCall = "call";
    	FindFunctions(FindIns,StrCall,iter);
    }
	
    void FindFunctions(ArrayList<String> FindIns, String StrCall, SymbolIterator iter) {
    	boolean index;
        while (iter.hasNext()) {
            Symbol sym = iter.next();
            if (sym != null) {
            	ColorizingService service = state.getTool().getService(ColorizingService.class);
            	
	            	for (int i=0;i<FindIns.size();++i) {
		    			if(sym.getName().toString().toLowerCase().contains(FindIns.get(i).toLowerCase()) == true) {
		    				println(sym.getName());                
		    				for ( Reference reference : sym.getReferences() ) {
		    					if(reference.getFromAddress()!=null){
		    						Address adr = reference.getFromAddress();
		    						for (Instruction ins : currentProgram.getListing().getInstructions(adr, true)){
		    						if(ins.toString().toLowerCase().contains(StrCall.toLowerCase()) == true) {
		    							println("	" + adr.toString() + "			" + ins.toString());
		    							service.setBackgroundColor(adr, adr,new Color(0xff,0x49,0x1b));
		    							break;
		    						}   	
		    					}
		    				}	
		    			}
		    		}
	    		}
            }
        }
    }
}
