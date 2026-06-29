// DecompList — decompile functions at a comma-separated list of addresses (script arg) in the current
// program. Used to dump T1Vista AI crash sites and the ServerSidePlugin handler. Output: re/decomplist.txt (append)
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.app.decompiler.*;
import java.io.*;

public class DecompList extends GhidraScript {
  public void run() throws Exception {
    String[] args=getScriptArgs();
    String list = args.length>0 ? args[0] : "";
    AddressSpace sp=currentProgram.getAddressFactory().getDefaultAddressSpace();
    FunctionManager fm=currentProgram.getFunctionManager();
    DecompInterface di=new DecompInterface(); di.openProgram(currentProgram);
    Listing lst=currentProgram.getListing();
    PrintWriter pw=new PrintWriter(new BufferedWriter(new FileWriter(
      "C:\\Users\\Joe\\Desktop\\Tribes Browser Based\\re\\decomplist.txt", true)));
    pw.println("\n\n@@@@@@@@@@ program="+currentProgram.getName()+" @@@@@@@@@@");
    for(String tok: list.split(",")){
      tok=tok.trim(); if(tok.isEmpty()) continue;
      long va=Long.parseLong(tok.replace("0x",""),16);
      Address a=sp.getAddress(va);
      Function f=fm.getFunctionContaining(a);
      pw.println("\n======== addr 0x"+Long.toHexString(va)+" in "+(f!=null?f.getName()+" @0x"+Long.toHexString(f.getEntryPoint().getOffset()):"<no func>")+" ========");
      // a few instrs around the address
      Address ia=sp.getAddress(va-0x10);
      for(int i=0;i<14;i++){ Instruction ins=lst.getInstructionAt(ia); if(ins==null){ia=ia.add(1);continue;}
        pw.println(String.format("   0x%08x  %s%s", ins.getAddress().getOffset(), ins.toString(), ins.getAddress().getOffset()==va?"  <<<<":""));
        ia=ins.getAddress().add(ins.getLength()); }
      if(f!=null){ DecompileResults r=di.decompileFunction(f,90,monitor);
        pw.println("---- decompile ----");
        pw.println((r!=null&&r.decompileCompleted())? r.getDecompiledFunction().getC():"  <fail>"); }
    }
    pw.close();
    println("DecompList done for "+currentProgram.getName());
  }
}
