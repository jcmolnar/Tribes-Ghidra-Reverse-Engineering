// T1Server — find the dedicated-server loop + advanceToTime + sg.currentTime/timeBase for the
// freeze fix. Anchor: the server loop feeds advanceToTime((currentTime-timeBase)*0.001f), so find
// references to the float 0.001f (0x3a83126f) and decompile the server-loop-shaped caller.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.mem.*;
import ghidra.app.decompiler.*;
import java.io.*;
import java.util.*;

public class T1Server extends GhidraScript {
  public void run() throws Exception {
    Listing lst=currentProgram.getListing();
    FunctionManager fm=currentProgram.getFunctionManager();
    ReferenceManager rm=currentProgram.getReferenceManager();
    Memory mem=currentProgram.getMemory();
    DecompInterface di=new DecompInterface(); di.openProgram(currentProgram);
    PrintWriter pw=new PrintWriter(new BufferedWriter(new FileWriter(
      System.getProperty("user.home")+"/t1server.txt")));

    // find all addresses holding the float 0.001f = 0x3a83126f
    pw.println("===== references to 0.001f (0x3a83126f) =====");
    Set<Function> cands=new LinkedHashSet<>();
    AddressSetView init=mem.getLoadedAndInitializedAddressSet();
    for(MemoryBlock b: mem.getBlocks()){
      if(!b.isInitialized()) continue;
      Address a=b.getStart(), end=b.getEnd();
      while(a.compareTo(end)<0){
        try{ if((mem.getInt(a)&0xffffffffL)==0x3a83126fL){
          ReferenceIterator it=rm.getReferencesTo(a);
          while(it.hasNext()){ Reference r=it.next(); Function f=fm.getFunctionContaining(r.getFromAddress());
            if(f!=null){ cands.add(f); pw.println("  0.001f @0x"+Long.toHexString(a.getOffset())+" used by 0x"+Long.toHexString(r.getFromAddress().getOffset())+" in "+f.getName()+" @0x"+Long.toHexString(f.getEntryPoint().getOffset())); } }
        }}catch(Exception e){}
        a=a.add(1);
      }
    }
    // decompile candidates; the server loop reads two globals, multiplies by 0.001, calls advanceToTime,
    // and iterates object sets. Show those that look server-loop shaped.
    pw.println("\n===== candidate decompiles (look for: (gA-gB)*0.001, a CALL = advanceToTime, set iteration) =====");
    for(Function f: cands){
      if(f.getBody().getNumAddresses()>5000) continue;
      DecompileResults r=di.decompileFunction(f,80,monitor); if(r==null||!r.decompileCompleted()) continue;
      String c=r.getDecompiledFunction().getC();
      if(c.contains("0.001")){
        pw.println("\n----- "+f.getName()+" @0x"+Long.toHexString(f.getEntryPoint().getOffset())+" -----");
        String[] ls=c.split("\n"); int shown=0;
        for(String ln:ls){ if(ln.contains("0.001")||ln.contains("0x6a8")||ln.contains("+ 0x6c")||ln.contains("FUN_")||ln.contains("32")||ln.contains("advance")){ pw.println("    "+ln.trim()); if(++shown>30) break; } }
      }
    }
    pw.close(); println("wrote re/t1server.txt");
  }
}
