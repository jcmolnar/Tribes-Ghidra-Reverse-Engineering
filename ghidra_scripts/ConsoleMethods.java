// ConsoleMethods — decompile the engine console-namespace methods that the plugin descriptor's
// vtable[1..7] point at (T1Vista). One is addCommand(name,handler,usage,minArgs,maxArgs); identify
// it + its exact signature/namespace so the PlayerManager init can call it.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.app.decompiler.*;
import java.io.*;

public class ConsoleMethods extends GhidraScript {
  public void run() throws Exception {
    AddressSpace sp=currentProgram.getAddressFactory().getDefaultAddressSpace();
    Listing lst=currentProgram.getListing();
    DecompInterface di=new DecompInterface(); di.openProgram(currentProgram);
    PrintWriter pw=new PrintWriter(new BufferedWriter(new FileWriter(
      "C:\\Users\\Joe\\Desktop\\Tribes Browser Based\\re\\consolemethods.txt")));
    // vtable[1..7] targets + the 0x5f4280 used by FUN_10001191
    long[] fns={0x5f40d8L,0x5f450cL,0x5f3ff8L,0x5f3f10L,0x5f4138L,0x5f41a8L,0x5f3ddcL,0x5f4280L};
    for(long va:fns){
      Function f=currentProgram.getFunctionManager().getFunctionContaining(sp.getAddress(va));
      pw.println("\n========== 0x"+Long.toHexString(va)+(f!=null?" "+f.getName():"")+" ==========");
      if(f!=null){
        DecompileResults r=di.decompileFunction(f,60,monitor);
        if(r!=null&&r.decompileCompleted()){ String c=r.getDecompiledFunction().getC();
          pw.println(c.length()>2600?c.substring(0,2600):c); }
        // first ~16 instructions (calling convention: ECX=this? args?)
        pw.println("  --- disasm head ---");
        Address cur=f.getEntryPoint();
        for(int i=0;i<16;i++){ Instruction ins=lst.getInstructionAt(cur); if(ins==null)break;
          pw.println(String.format("    0x%08x  %s",cur.getOffset(),ins.toString()));
          cur=cur.add(ins.getLength()); if(!f.getBody().contains(cur))break; }
      }
    }
    pw.close(); println("wrote re/consolemethods.txt");
  }
}
