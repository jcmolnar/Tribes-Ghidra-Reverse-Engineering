// T1More — (1) find createDataBlock (a fn with a big jumptable switch = the datablock-type switch);
//          (2) confirm Lightning/PSC candidates by decompile.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.app.decompiler.*;
import java.io.*;

public class T1More extends GhidraScript {
  public void run() throws Exception {
    AddressSpace sp=currentProgram.getAddressFactory().getDefaultAddressSpace();
    Listing lst=currentProgram.getListing();
    DecompInterface di=new DecompInterface(); di.openProgram(currentProgram);
    PrintWriter pw=new PrintWriter(new BufferedWriter(new FileWriter(
      "C:\\Users\\Joe\\Desktop\\Tribes Browser Based\\re\\t1more.txt")));

    // (1) functions with a big switch (an instruction with many flow targets) — createDataBlock candidate
    pw.println("===== (1) big-switch functions (>=12 jump targets) — createDataBlock candidate =====");
    int shown=0;
    for(Function f: currentProgram.getFunctionManager().getFunctions(true)){
      long n=f.getBody().getNumAddresses(); if(n<150||n>4000) continue;
      Address cur=f.getEntryPoint(); int maxFlows=0; Address swAt=null;
      for(int i=0;i<2000;i++){ Instruction ins=lst.getInstructionAt(cur); if(ins==null) break;
        if(ins.getMnemonicString().startsWith("JMP")){ Address[] fl=ins.getFlows(); if(fl!=null&&fl.length>maxFlows){maxFlows=fl.length;swAt=cur;} }
        cur=cur.add(ins.getLength()); if(!f.getBody().contains(cur)) break; }
      if(maxFlows>=12&&shown<10){ pw.println("  "+f.getName()+" @0x"+Long.toHexString(f.getEntryPoint().getOffset())+"  switch@0x"+Long.toHexString(swAt.getOffset())+" ("+maxFlows+" cases, size "+n+")");
        // is it createDataBlock? decompile head, look for operator_new + unpack-less return of obj
        DecompileResults r=di.decompileFunction(f,30,monitor);
        if(r!=null&&r.decompileCompleted()){ String[] ls=r.getDecompiledFunction().getC().split("\n");
          for(int k=0;k<Math.min(ls.length,6);k++) pw.println("       "+ls[k]); }
        shown++; }
    }

    // (2) confirm Lightning/PSC candidates
    pw.println("\n===== (2) candidate fn decompiles =====");
    long[] cand={0x4693a0L,0x469640L,0x405ec8L};
    for(long va:cand){
      Function f=currentProgram.getFunctionManager().getFunctionContaining(sp.getAddress(va));
      pw.println("\n--- "+(f!=null?f.getName():"?")+" @0x"+Long.toHexString(va)+" ---");
      if(f!=null){ DecompileResults r=di.decompileFunction(f,60,monitor);
        if(r!=null&&r.decompileCompleted()){ String[] ls=r.getDecompiledFunction().getC().split("\n");
          for(int k=0;k<Math.min(ls.length,46);k++) pw.println("  "+ls[k]); } }
    }
    pw.close(); println("wrote re/t1more.txt");
  }
}
