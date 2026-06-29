// FollowRender — from the interior-piece render seeds (FUN_004fb4cc / FUN_004fb748), decompile
// each seed + disasm, then decompile every direct CALL target one level deep. Goal: reach the
// per-surface texture-bind / texgen choke point so we can pick a detour site + read the GFXBitmap
// pointer flow. Output: re/followrender.txt
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.app.decompiler.*;
import java.io.*;
import java.util.*;

public class FollowRender extends GhidraScript {
  PrintWriter pw; DecompInterface di; AddressSpace sp; Memory mem; FunctionManager fm;
  long textMin = 0x00401000L, textMax = 0x0060e000L;

  Function getfn(long va){
    Function f=fm.getFunctionContaining(sp.getAddress(va));
    if(f==null){ try{disassemble(sp.getAddress(va)); f=createFunction(sp.getAddress(va),null);}catch(Exception e){} }
    return f;
  }
  String decomp(Function f){
    if(f==null) return "  <no fn>";
    DecompileResults r=di.decompileFunction(f,90,monitor);
    return "FUN_"+Long.toHexString(f.getEntryPoint().getOffset())+" (size "+f.getBody().getNumAddresses()+"):\n"
      +((r!=null&&r.decompileCompleted())?r.getDecompiledFunction().getC():"<decompile fail>");
  }
  // disasm + collect direct CALL targets
  Set<Long> disasmAndCalls(Function f){
    Set<Long> calls=new LinkedHashSet<Long>();
    if(f==null) return calls;
    pw.println("  ---- disasm FUN_"+Long.toHexString(f.getEntryPoint().getOffset())+" ----");
    InstructionIterator it=currentProgram.getListing().getInstructions(f.getBody(),true);
    while(it.hasNext()){ Instruction ins=it.next(); StringBuilder b=new StringBuilder();
      try{for(byte x:ins.getBytes())b.append(String.format("%02x ",x&0xff));}catch(Exception e){}
      pw.println(String.format("    0x%08x  %-22s %s",ins.getAddress().getOffset(),b.toString().trim(),ins.toString()));
      String m=ins.getMnemonicString().toLowerCase();
      if(m.equals("call")){
        for(int oi=0;oi<ins.getNumOperands();oi++){
          Object[] objs=ins.getOpObjects(oi);
          for(Object o:objs) if(o instanceof Address){ long t=((Address)o).getOffset(); if(t>=textMin&&t<textMax) calls.add(t); }
        }
      }
    }
    return calls;
  }
  public void run() throws Exception {
    sp=currentProgram.getAddressFactory().getDefaultAddressSpace(); mem=currentProgram.getMemory();
    fm=currentProgram.getFunctionManager();
    di=new DecompInterface(); di.openProgram(currentProgram);
    pw=new PrintWriter(new BufferedWriter(new FileWriter(System.getProperty("user.home")+"/followrender.txt")));

    long[] seeds={0x4fb0e4L};
    Set<Long> level1=new LinkedHashSet<Long>();
    for(long s:seeds){
      Function f=getfn(s);
      pw.println("\n################ SEED FUN_"+Long.toHexString(s)+" ################");
      pw.println(decomp(f));
      level1.addAll(disasmAndCalls(f));
    }
    pw.println("\n\n=========================== LEVEL-1 CALLEES ===========================");
    pw.println("callees: "+level1);
    for(long c:level1){
      Function f=getfn(c);
      pw.println("\n################ CALLEE FUN_"+Long.toHexString(c)+" ################");
      pw.println(decomp(f));
      disasmAndCalls(f); // disasm only (don't recurse further)
    }
    pw.close();
    println("wrote re/followrender.txt; level1="+level1);
  }
}
