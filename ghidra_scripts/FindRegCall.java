// FindRegCall — locate how the engine registers getNumClients (StringCallback handler 0x0041e094)
// inside the big registrar FUN_00423158: dump the instruction window around references to 0x41e094 /
// 0x41e0cc so we see name/handler/minArgs/maxArgs + which addCommand (0x5f40d8 vs 0x5f4138) it calls.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import java.io.*;
import java.util.*;

public class FindRegCall extends GhidraScript {
  public void run() throws Exception {
    AddressSpace sp=currentProgram.getAddressFactory().getDefaultAddressSpace();
    Listing lst=currentProgram.getListing();
    PrintWriter pw=new PrintWriter(new BufferedWriter(new FileWriter(
      "C:\\Users\\Joe\\Desktop\\Tribes Browser Based\\re\\findreg.txt")));
    Function f=currentProgram.getFunctionManager().getFunctionContaining(sp.getAddress(0x423158L));
    if(f==null){ pw.println("no fn @0x423158"); pw.close(); return; }
    ArrayList<String> lines=new ArrayList<>();
    ArrayList<Long> addrs=new ArrayList<>();
    Address cur=f.getEntryPoint();
    for(int i=0;i<8000;i++){ Instruction ins=lst.getInstructionAt(cur); if(ins==null)break;
      lines.add(ins.toString()); addrs.add(cur.getOffset());
      cur=cur.add(ins.getLength()); if(!f.getBody().contains(cur))break;
    }
    for(int i=0;i<lines.size();i++){
      String s=lines.get(i);
      if(s.contains("41e094")||s.contains("41e0cc")||s.contains("41e140")){
        pw.println("\n--- window around "+s+" @0x"+Long.toHexString(addrs.get(i))+" ---");
        for(int j=Math.max(0,i-11); j<=Math.min(lines.size()-1,i+6); j++)
          pw.println(String.format("    0x%08x  %s%s",addrs.get(j),lines.get(j), j==i?"   <==":""));
      }
    }
    pw.close(); println("wrote re/findreg.txt");
  }
}
