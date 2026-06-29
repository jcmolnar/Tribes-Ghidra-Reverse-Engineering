// V7h — disassemble the gap [0x4c1d5e,0x4c2198] (onWake+onPreRender), define functions at RET boundaries,
// decompile the function containing the qsort comparator refs (0x4c211f / 0x4c2177) = onPreRender, dump disasm.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.app.decompiler.*;
import java.io.*;
import java.util.*;

public class V7h extends GhidraScript {
  PrintWriter pw; DecompInterface di; AddressSpace sp;
  void disasm(long start, long end) {
    InstructionIterator it = currentProgram.getListing().getInstructions(sp.getAddress(start), true);
    while (it.hasNext()) {
      Instruction ins = it.next();
      if (ins.getAddress().getOffset() > end) break;
      StringBuilder b = new StringBuilder();
      try { for (byte x : ins.getBytes()) b.append(String.format("%02x ", x&0xff)); } catch(Exception e){}
      pw.println(String.format("    0x%08x  %-22s %s", ins.getAddress().getOffset(), b.toString().trim(), ins.toString()));
    }
  }
  public void run() throws Exception {
    sp = currentProgram.getAddressFactory().getDefaultAddressSpace();
    di = new DecompInterface(); di.openProgram(currentProgram);
    pw = new PrintWriter(new BufferedWriter(new FileWriter(
        "C:\\Users\\Joe\\Desktop\\Tribes Browser Based\\re\\v7h.txt")));

    long lo=0x4c1d5eL, hi=0x4c2198L;
    // clear and disassemble linearly across the gap
    for (long a=lo; a<hi; ) {
      Instruction ins = getInstructionAt(sp.getAddress(a));
      if (ins==null) { try{ disassemble(sp.getAddress(a)); }catch(Exception e){} ins=getInstructionAt(sp.getAddress(a)); }
      if (ins==null) { a++; continue; }
      a = ins.getAddress().getOffset() + ins.getLength();
    }
    // define functions at boundaries: instruction right after a RET (c3/c2xx) that isn't already in a fn
    InstructionIterator it = currentProgram.getListing().getInstructions(sp.getAddress(lo), true);
    boolean prevRet=true; // start of gap begins a function
    List<Long> starts=new ArrayList<Long>();
    while (it.hasNext()){
      Instruction ins=it.next(); long a=ins.getAddress().getOffset(); if(a>=hi)break;
      if (prevRet){ starts.add(a); prevRet=false; }
      String m=ins.getMnemonicString();
      if (m.equals("RET")||m.equals("RETN")) prevRet=true;
    }
    pw.println("function starts in gap: "+starts.size());
    for (long s: starts){
      try{ if(getFunctionAt(sp.getAddress(s))==null) createFunction(sp.getAddress(s),null); }catch(Exception e){}
      pw.println("  start 0x"+Long.toHexString(s));
    }

    // decompile the function containing 0x4c211f (onPreRender)
    Function pr = getFunctionContaining(sp.getAddress(0x4c211fL));
    pw.println("\n================ onPreRender = FUN_"+(pr!=null?Long.toHexString(pr.getEntryPoint().getOffset()):"?")+" ================");
    if (pr!=null){
      DecompileResults r=di.decompileFunction(pr,120,monitor);
      pw.println("---- decompile ----");
      pw.println((r!=null&&r.decompileCompleted())?r.getDecompiledFunction().getC():"<fail>");
      pw.println("---- disasm ----");
      disasm(pr.getEntryPoint().getOffset(), pr.getBody().getMaxAddress().getOffset());
    } else {
      pw.println("no function — raw disasm of gap:");
      disasm(lo,hi);
    }
    pw.close();
    println("wrote re/v7h.txt; onPreRender="+(pr!=null?Long.toHexString(pr.getEntryPoint().getOffset()):"?"));
  }
}
