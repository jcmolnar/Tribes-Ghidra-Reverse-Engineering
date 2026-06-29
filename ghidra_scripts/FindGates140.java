// FindGates140 — find EVERY function that references serverNetcodeVersion (0x6D0FF8) / ourNetcodeVersion
// (0x6D0FFC), i.e. every netcode-version-gated code path in the binary. Decompile each. -> re/version_gates_140.txt
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.app.decompiler.*;
import java.io.*;
import java.util.*;

public class FindGates140 extends GhidraScript {
  public void run() throws Exception {
    AddressSpace sp=currentProgram.getAddressFactory().getDefaultAddressSpace();
    ReferenceManager rm=currentProgram.getReferenceManager();
    FunctionManager fm=currentProgram.getFunctionManager();
    DecompInterface di=new DecompInterface(); di.openProgram(currentProgram);
    long[] gates={0x6d0ff8L, 0x6d0ffcL};
    LinkedHashMap<Long,String> funcs=new LinkedHashMap<Long,String>();
    for(long g: gates){
      Address ga=sp.getAddress(g);
      ReferenceIterator it=rm.getReferencesTo(ga);
      while(it.hasNext()){
        Reference r=it.next();
        Address from=r.getFromAddress();
        Function f=fm.getFunctionContaining(from);
        long key = f!=null? f.getEntryPoint().getOffset() : from.getOffset();
        String nm = f!=null? f.getName(true) : ("<no-func@0x"+Long.toHexString(from.getOffset())+">");
        if(!funcs.containsKey(key)) funcs.put(key, nm+"  (gate 0x"+Long.toHexString(g)+" ref @0x"+Long.toHexString(from.getOffset())+")");
      }
    }
    PrintWriter pw=new PrintWriter(new BufferedWriter(new FileWriter(System.getProperty("user.home")+"/version_gates_140.txt")));
    pw.println("Functions referencing serverNetcodeVersion(0x6D0FF8)/ourNetcodeVersion(0x6D0FFC) — every netcode gate.");
    pw.println("Count: "+funcs.size()+"\n");
    for(Map.Entry<Long,String> e: funcs.entrySet()) pw.println(String.format("0x%08x  %s", e.getKey(), e.getValue()));
    pw.println("\n\n==================== DECOMPILES ====================");
    for(Map.Entry<Long,String> e: funcs.entrySet()){
      pw.println("\n======== 0x"+Long.toHexString(e.getKey())+"  "+e.getValue()+" ========");
      Address a=sp.getAddress(e.getKey()); Function f=fm.getFunctionAt(a);
      if(f==null){ pw.println("  <no func>"); continue; }
      DecompileResults r=di.decompileFunction(f,60,monitor);
      pw.println((r!=null&&r.decompileCompleted())? r.getDecompiledFunction().getC() : "  <fail>");
      monitor.checkCancelled();
    }
    pw.close();
    println("gates="+funcs.size()+" -> re/version_gates_140.txt");
    StringBuilder sb=new StringBuilder(); for(String v: funcs.values()) sb.append("\n  ").append(v);
    println("FUNCS:"+sb);
  }
}
