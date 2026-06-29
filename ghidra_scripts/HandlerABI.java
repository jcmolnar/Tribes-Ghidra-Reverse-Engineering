// HandlerABI — decompile two known engine StringCallback console handlers (getNumClients 0x41e094,
// getClientByIndex 0x41e0cc) + the console invoker, to lock the handler ABI (how SimObject*/argc/argv
// arrive, return char*, ret N) so the PlayerManager command shims match exactly.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.app.decompiler.*;
import java.io.*;

public class HandlerABI extends GhidraScript {
  public void run() throws Exception {
    AddressSpace sp=currentProgram.getAddressFactory().getDefaultAddressSpace();
    Listing lst=currentProgram.getListing();
    DecompInterface di=new DecompInterface(); di.openProgram(currentProgram);
    PrintWriter pw=new PrintWriter(new BufferedWriter(new FileWriter(
      System.getProperty("user.home")+"/handlerabi.txt")));
    long[] fns={0x41e094L,0x41e0ccL,0x41e140L};
    for(long va:fns){
      Function f=currentProgram.getFunctionManager().getFunctionContaining(sp.getAddress(va));
      pw.println("\n========== 0x"+Long.toHexString(va)+(f!=null?" "+f.getName():"")+" ==========");
      if(f!=null){
        DecompileResults r=di.decompileFunction(f,60,monitor);
        if(r!=null&&r.decompileCompleted()){ String c=r.getDecompiledFunction().getC();
          pw.println(c.length()>1800?c.substring(0,1800):c); }
        pw.println("  --- disasm head (prologue = ABI) ---");
        Address cur=f.getEntryPoint();
        for(int i=0;i<14;i++){ Instruction ins=lst.getInstructionAt(cur); if(ins==null)break;
          pw.println(String.format("    0x%08x  %s",cur.getOffset(),ins.toString()));
          cur=cur.add(ins.getLength()); if(!f.getBody().contains(cur))break; }
        // tail: find the RET to see ret N (stack cleanup = arg count)
        Address end=f.getBody().getMaxAddress();
        Instruction ti=lst.getInstructionBefore(end);
        for(int k=0;k<6 && ti!=null;k++){ if(ti.toString().startsWith("RET")){ pw.println("    TAIL: "+ti.toString()); break; } ti=lst.getInstructionBefore(ti.getAddress()); }
      }
    }
    pw.close(); println("wrote re/handlerabi.txt");
  }
}
