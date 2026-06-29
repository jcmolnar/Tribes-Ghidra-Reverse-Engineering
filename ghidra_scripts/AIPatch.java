// AIPatch — in ServerSidePlugin.dll (Bov), find the AI-crash-fix installer (refs the "Patching an AI crash
// bug" string), decompile it to extract the T1Vista target address + patch bytes (VirtualProtect+write).
// Output: re/aipatch.txt
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.app.decompiler.*;
import java.io.*;
import java.util.*;

public class AIPatch extends GhidraScript {
  DecompInterface di; FunctionManager fm; PrintWriter pw; Set<Long> done=new HashSet<Long>();
  void deco(Function f, String why){
    if(f==null) return; long k=f.getEntryPoint().getOffset(); if(!done.add(k)) return;
    pw.println("\n======== "+f.getName()+" @0x"+Long.toHexString(k)+"  ["+why+"] ========");
    DecompileResults r=di.decompileFunction(f,90,monitor);
    pw.println((r!=null&&r.decompileCompleted())? r.getDecompiledFunction().getC():"  <fail>");
  }
  void refsTo(String s) throws Exception {
    pw.println("\n##### refs to \""+s+"\" #####");
    Address a=find(s);
    if(a==null){ pw.println("  <not found>"); return; }
    pw.println("  @0x"+Long.toHexString(a.getOffset()));
    ReferenceManager rm=currentProgram.getReferenceManager();
    ReferenceIterator it=rm.getReferencesTo(a);
    while(it.hasNext()){ Reference r=it.next(); Function f=fm.getFunctionContaining(r.getFromAddress());
      pw.println("   xref 0x"+Long.toHexString(r.getFromAddress().getOffset())+" in "+(f!=null?f.getName():"?"));
      deco(f,"refs string"); }
  }
  public void run() throws Exception {
    di=new DecompInterface(); di.openProgram(currentProgram);
    fm=currentProgram.getFunctionManager();
    pw=new PrintWriter(new BufferedWriter(new FileWriter(System.getProperty("user.home")+"/aipatch.txt")));
    pw.println("ServerSidePlugin.dll (Bov) — AI crash-fix patch installer");
    refsTo("Patching an AI crash bug");
    refsTo("Patching a hook into the AI");
    refsTo("nearly crashed you");
    // also list functions that call VirtualProtect (the patchers)
    pw.println("\n##### VirtualProtect callers (patch routines) #####");
    SymbolIterator si=currentProgram.getSymbolTable().getAllSymbols(true);
    ReferenceManager rm=currentProgram.getReferenceManager();
    while(si.hasNext()){ Symbol s=si.next(); if(!s.getName().equals("VirtualProtect")) continue;
      ReferenceIterator it=rm.getReferencesTo(s.getAddress());
      while(it.hasNext()){ Function f=fm.getFunctionContaining(it.next().getFromAddress()); deco(f,"calls VirtualProtect"); } }
    pw.close();
    println("wrote re/aipatch.txt");
  }
}
