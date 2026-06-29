// ArmGate — confirm the arm-aim lever: who CALLS the arm-aim apply FUN_00412f94 (ghost render path?),
// and where player+0x4c bit1 (&2) is SET (the flag that makes the owner skip arm-aim). That tells us
// whether forcing the FUN_00412f94 gate to always-skip is the right patch to make ghost arms animate.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.app.decompiler.*;
import java.io.*;
import java.util.*;

public class ArmGate extends GhidraScript {
  PrintWriter pw; DecompInterface di; AddressSpace sp;
  String deco(long va){ Function f=getFunctionContaining(sp.getAddress(va));
    if(f==null) return "  <no fn>"; DecompileResults r=di.decompileFunction(f,120,monitor);
    return "FUN_"+Long.toHexString(f.getEntryPoint().getOffset())+":\n"+((r!=null&&r.decompileCompleted())?r.getDecompiledFunction().getC():"<fail>"); }
  public void run() throws Exception {
    sp=currentProgram.getAddressFactory().getDefaultAddressSpace();
    di=new DecompInterface(); di.openProgram(currentProgram);
    pw=new PrintWriter(new BufferedWriter(new FileWriter("C:\\Users\\Joe\\Desktop\\Tribes Browser Based\\re\\armgate.txt")));

    pw.println("===== callers of arm-aim apply FUN_00412f94 =====");
    Set<Long> callers=new LinkedHashSet<Long>();
    ReferenceIterator it=currentProgram.getReferenceManager().getReferencesTo(sp.getAddress(0x412f94L));
    while(it.hasNext()){ Reference r=it.next(); if(r.getReferenceType().isCall()){ Function f=getFunctionContaining(r.getFromAddress());
      if(f!=null){ callers.add(f.getEntryPoint().getOffset()); pw.println("  call @0x"+Long.toHexString(r.getFromAddress().getOffset())+" in FUN_"+Long.toHexString(f.getEntryPoint().getOffset())); } } }
    for(long c: callers) pw.println("\n######## "+deco(c));

    // where is byte [reg+0x4c] |= 2 set?  (OR byte ptr [reg+0x4c], 0x2  = 80 4? 4c 02)  + the gate disasm
    pw.println("\n===== instructions doing OR byte [reg+0x4c],imm  (the +0x4c flag writes) =====");
    InstructionIterator ii=currentProgram.getListing().getInstructions(true);
    while(ii.hasNext()){ Instruction ins=ii.next(); String t=ins.toString();
      if((t.startsWith("OR byte ptr")||t.startsWith("AND byte ptr")||t.startsWith("MOV byte ptr")) && t.contains("0x4c")){
        Function f=getFunctionContaining(ins.getAddress());
        pw.println(String.format("  0x%08x  %-34s  in FUN_%08x", ins.getAddress().getOffset(), t, f!=null?f.getEntryPoint().getOffset():0)); } }
    pw.close(); println("wrote re/armgate.txt; callers="+callers);
  }
}
