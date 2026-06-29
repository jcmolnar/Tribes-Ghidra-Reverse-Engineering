// WrapDisasm — full byte-level disasm of ServerSidePlugin's reg wrappers FUN_10007fd9 (command, via
// the 12-byte table {name,handler,argInfo}) + FUN_10007fbe (var, 8-byte table). Shows the EXACT
// ECX/EDX/EAX/stack setup before the engine console call = the proven template to replicate.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import java.io.*;

public class WrapDisasm extends GhidraScript {
  public void run() throws Exception {
    AddressSpace sp=currentProgram.getAddressFactory().getDefaultAddressSpace();
    Listing lst=currentProgram.getListing();
    PrintWriter pw=new PrintWriter(new BufferedWriter(new FileWriter(
      "C:\\Users\\Joe\\Desktop\\Tribes Browser Based\\re\\wrapdisasm.txt")));
    long[] fns={0x10007fd9L,0x10007fbeL,0x10007f98L};
    for(long va:fns){
      Function f=currentProgram.getFunctionManager().getFunctionContaining(sp.getAddress(va));
      pw.println("\n===== 0x"+Long.toHexString(va)+(f!=null?" "+f.getName():"")+" =====");
      Address cur=sp.getAddress(va);
      for(int i=0;i<40;i++){ Instruction ins=lst.getInstructionAt(cur); if(ins==null)break;
        byte[] b=ins.getBytes(); StringBuilder hx=new StringBuilder();
        for(byte x:b) hx.append(String.format("%02x ",x&0xff));
        pw.println(String.format("  0x%08x  %-20s %s",cur.getOffset(),hx.toString(),ins.toString()));
        cur=cur.add(ins.getLength());
        if(f!=null && !f.getBody().contains(cur)) break;
        if(ins.toString().startsWith("RET")) break;
      }
    }
    pw.close(); println("wrote re/wrapdisasm.txt");
  }
}
