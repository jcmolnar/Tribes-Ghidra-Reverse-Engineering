// ArmAim — find the caller of the aim-direction selector FUN_00413074 (picks "front_middle"/"left_back"
// etc.), how the resulting aim pose is played on the arm thread, and where it's gated owner-vs-ghost
// (controlObject == this). That gate / thread-priority is the site to suppress for viewed players so the
// arms follow the action animation (like the owner path) instead of the weapon-aim pose.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.app.decompiler.*;
import java.io.*;
import java.util.*;

public class ArmAim extends GhidraScript {
  PrintWriter pw; DecompInterface di; AddressSpace sp;
  String deco(long va){ Function f=getFunctionContaining(sp.getAddress(va));
    if(f==null) return "  <no fn @0x"+Long.toHexString(va)+">";
    DecompileResults r=di.decompileFunction(f,120,monitor);
    return "FUN_"+Long.toHexString(f.getEntryPoint().getOffset())+" (size "+f.getBody().getNumAddresses()+"):\n"
      +((r!=null&&r.decompileCompleted())?r.getDecompiledFunction().getC():"<fail>"); }
  void disasm(long va){ Function f=getFunctionContaining(sp.getAddress(va)); if(f==null) return;
    pw.println("  ---- disasm FUN_"+Long.toHexString(f.getEntryPoint().getOffset())+" ----");
    InstructionIterator it=currentProgram.getListing().getInstructions(f.getBody(),true);
    while(it.hasNext()){ Instruction ins=it.next(); StringBuilder b=new StringBuilder();
      try{for(byte x:ins.getBytes())b.append(String.format("%02x ",x&0xff));}catch(Exception e){}
      pw.println(String.format("    0x%08x  %-20s %s",ins.getAddress().getOffset(),b.toString().trim(),ins.toString())); } }
  public void run() throws Exception {
    sp=currentProgram.getAddressFactory().getDefaultAddressSpace();
    di=new DecompInterface(); di.openProgram(currentProgram);
    pw=new PrintWriter(new BufferedWriter(new FileWriter(System.getProperty("user.home")+"/armaim.txt")));

    long sel=0x413074L;  // aim-direction selector
    pw.println("===== callers of aim-direction selector FUN_00413074 =====");
    Set<Long> callers=new LinkedHashSet<Long>();
    ReferenceIterator it=currentProgram.getReferenceManager().getReferencesTo(sp.getAddress(sel));
    while(it.hasNext()){ Reference r=it.next(); if(r.getReferenceType().isCall()){ Function f=getFunctionContaining(r.getFromAddress());
      if(f!=null){ callers.add(f.getEntryPoint().getOffset()); pw.println("  call @0x"+Long.toHexString(r.getFromAddress().getOffset())+" in FUN_"+Long.toHexString(f.getEntryPoint().getOffset())); } } }
    for(long c: callers){ pw.println("\n######## caller decompile:\n"+deco(c)); pw.println(); disasm(c); }
    pw.close();
    println("wrote re/armaim.txt; callers="+callers);
  }
}
