// OverrideApply — find where the shape-instance override-select byte (+0x9e) is READ/applied, to learn
// what value disables the lowerback override (is index 2 really "no override"?). Also dump the looks
// setPriority target FUN_005bd9a0 (what it controls) so we know whether the looks thread is the locker.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.scalar.*;
import ghidra.app.decompiler.*;
import java.io.*;
import java.util.*;

public class OverrideApply extends GhidraScript {
  PrintWriter pw; DecompInterface di; AddressSpace sp;
  String deco(long va){
    Function f=getFunctionContaining(sp.getAddress(va));
    if(f==null) return "  <no fn>";
    DecompileResults r=di.decompileFunction(f,120,monitor);
    return "FUN_"+Long.toHexString(f.getEntryPoint().getOffset())+" (size "+f.getBody().getNumAddresses()+"):\n"
      +((r!=null&&r.decompileCompleted())?r.getDecompiledFunction().getC():"<fail>");
  }
  public void run() throws Exception {
    sp=currentProgram.getAddressFactory().getDefaultAddressSpace();
    di=new DecompInterface(); di.openProgram(currentProgram);
    pw=new PrintWriter(new BufferedWriter(new FileWriter(System.getProperty("user.home")+"/overrideapply.txt")));

    // 1) functions that READ byte [reg+0x9e] (the override-select). Exclude the writes in updateAnimation
    //    (those are MOV byte [reg+0x9e], imm = mnemonic MOV with a dest mem operand + imm src).
    pw.println("===== instructions touching [reg+0x9e] (byte) =====");
    Set<Long> readers=new LinkedHashSet<Long>();
    InstructionIterator it=currentProgram.getListing().getInstructions(true);
    while(it.hasNext()){ Instruction ins=it.next();
      boolean has9e=false;
      for(int oi=0;oi<ins.getNumOperands();oi++) for(Object o:ins.getOpObjects(oi))
        if(o instanceof Scalar && ((Scalar)o).getUnsignedValue()==0x9e) has9e=true;
      if(!has9e) continue;
      String m=ins.getMnemonicString();
      // skip the inline setOverride writes (MOVZX/MOV reads are what we want)
      boolean isRead = m.startsWith("MOVZX")||m.startsWith("MOVSX")||(m.equals("MOV")&&ins.getResultObjects().length>0 && !ins.toString().contains(",0x"))||m.startsWith("CMP")||m.startsWith("TEST");
      long fa=0; Function f=getFunctionContaining(ins.getAddress()); if(f!=null) fa=f.getEntryPoint().getOffset();
      pw.println(String.format("  0x%08x  %-40s  fn=FUN_%08x  %s", ins.getAddress().getOffset(), ins.toString(), fa, isRead?"<READ>":""));
      if(isRead && f!=null) readers.add(fa);
    }
    pw.println("\n===== decompile reader functions (the override-apply) =====");
    for(long fn: readers){ pw.println("\n######## "+deco(fn)); }

    // 2) the looks setPriority target (called right after each setOverride in updateAnimation)
    pw.println("\n\n===== FUN_005bd9a0 (the setPriority called after setOverride; EDX=priority) =====");
    pw.println(deco(0x5bd9a0L));

    pw.close();
    println("wrote re/overrideapply.txt; readers="+readers);
  }
}
