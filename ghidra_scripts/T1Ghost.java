// T1Ghost — dump resolveGhost (FUN_005535d8) callers with full context (vectors 3-5:
// Player mount / Lightning / PSC ctrl-obj), + find createDataBlock via preloadServerDataBlocks.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.app.decompiler.*;
import java.io.*;
import java.util.*;

public class T1Ghost extends GhidraScript {
  public void run() throws Exception {
    AddressSpace sp=currentProgram.getAddressFactory().getDefaultAddressSpace();
    Listing lst=currentProgram.getListing();
    FunctionManager fm=currentProgram.getFunctionManager();
    ReferenceManager rm=currentProgram.getReferenceManager();
    DecompInterface di=new DecompInterface(); di.openProgram(currentProgram);
    PrintWriter pw=new PrintWriter(new BufferedWriter(new FileWriter(
      System.getProperty("user.home")+"/t1ghost.txt")));

    // resolveGhost callers, full context
    pw.println("===== resolveGhost = FUN_005535d8 callers (16 instrs each) =====");
    Address ta=sp.getAddress(0x5535d8L);
    ReferenceIterator it=rm.getReferencesTo(ta); List<Address> cs=new ArrayList<>();
    while(it.hasNext()){ Reference r=it.next(); if(r.getReferenceType().isCall()) cs.add(r.getFromAddress()); }
    Collections.sort(cs);
    for(Address ca:cs){
      Function f=fm.getFunctionContaining(ca);
      pw.println("\n  === caller 0x"+Long.toHexString(ca.getOffset())+(f!=null?" in "+f.getName()+" @0x"+Long.toHexString(f.getEntryPoint().getOffset()):"")+" ===");
      Address cur=ca;
      for(int i=0;i<16;i++){ Instruction ins=lst.getInstructionAt(cur); if(ins==null) break; String s=ins.toString();
        String tag=""; if(s.startsWith("CALL")&&!s.contains("0x5535d8")&&i>0) tag="  (call)";
        if(s.startsWith("TEST")||s.startsWith("CMP")) tag="  <-- test";
        byte[] ib=ins.getBytes(); StringBuilder h=new StringBuilder(); for(byte b:ib) h.append(String.format("%02x ",b&0xff));
        pw.println(String.format("    0x%08x  %-22s %-32s%s", cur.getOffset(), h.toString(), s, tag));
        cur=cur.add(ins.getLength()); if(ins.getFlowType().isTerminal()) break; }
    }

    // find createDataBlock via preloadServerDataBlocks FUN_00423158 (calls it)
    pw.println("\n===== preloadServerDataBlocks FUN_00423158 decompile (find createDataBlock) =====");
    Function pf=fm.getFunctionContaining(sp.getAddress(0x423158L));
    if(pf!=null){ DecompileResults r=di.decompileFunction(pf,60,monitor);
      if(r!=null&&r.decompileCompleted()){ String[] ls=r.getDecompiledFunction().getC().split("\n");
        for(String ln:ls) if(ln.contains("FUN_")||ln.contains("createDataBlock")||ln.contains("unpack")||ln.contains("DataBlock")) pw.println("    "+ln.trim()); } }
    pw.close(); println("wrote re/t1ghost.txt");
  }
}
