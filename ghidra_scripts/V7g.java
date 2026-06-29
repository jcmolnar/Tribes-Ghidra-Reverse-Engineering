// V7g — find onPreRender: byte-scan .text for refs to the compare fns 0x4c1c5c/0x4c1c7c (qsort args),
// and force-disassemble the undisassembled gap [0x4c1d5e,0x4c2198] (onWake+onPreRender). Decompile+disasm.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.app.decompiler.*;
import java.io.*;
import java.util.*;

public class V7g extends GhidraScript {
  PrintWriter pw; DecompInterface di; AddressSpace sp; Memory mem;
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
  String deco(long va) {
    Function f = getFunctionContaining(sp.getAddress(va));
    if (f==null){ try{disassemble(sp.getAddress(va)); f=createFunction(sp.getAddress(va),null);}catch(Exception e){} }
    if (f==null) return "  <no fn>";
    DecompileResults r = di.decompileFunction(f, 120, monitor);
    return (r!=null&&r.decompileCompleted())? r.getDecompiledFunction().getC():"  <fail>";
  }
  public void run() throws Exception {
    sp = currentProgram.getAddressFactory().getDefaultAddressSpace();
    mem = currentProgram.getMemory();
    di = new DecompInterface(); di.openProgram(currentProgram);
    pw = new PrintWriter(new BufferedWriter(new FileWriter(
        "C:\\Users\\Joe\\Desktop\\Tribes Browser Based\\re\\v7g.txt")));

    // force-disassemble the gap (and the onWake region just before onRenderCell)
    long gapLo=0x4c1d60L, gapHi=0x4c2198L;
    pw.println("force-disassembling gap [0x"+Long.toHexString(gapLo)+",0x"+Long.toHexString(gapHi)+"]");
    // Try to create functions at likely starts: scan for PUSH EBP (55 8B EC) prologues.
    MemoryBlock tb=mem.getBlock(".text");
    byte[] buf=new byte[(int)(gapHi-gapLo)];
    mem.getBytes(sp.getAddress(gapLo), buf);
    List<Long> prologues=new ArrayList<Long>();
    for(int i=0;i+2<buf.length;i++){
      if((buf[i]&0xff)==0x55 && (buf[i+1]&0xff)==0x8b && (buf[i+2]&0xff)==0xec) prologues.add(gapLo+i);
      // Borland also: 53 56 57 (push ebx/esi/edi) or 55 8bec
    }
    pw.println("PUSH EBP;MOV EBP,ESP prologues in gap: "+prologues.size());
    for(long p: prologues){
      pw.println("  candidate fn @0x"+Long.toHexString(p));
      try{ disassemble(sp.getAddress(p)); if(getFunctionAt(sp.getAddress(p))==null) createFunction(sp.getAddress(p),null);}catch(Exception e){}
    }
    // also just disassemble linearly from gapLo
    try{ disassemble(sp.getAddress(gapLo)); }catch(Exception e){}

    // byte-scan whole .text for refs to compare fns (LE addr) to find onPreRender's qsort calls
    long ts=tb.getStart().getOffset(), te=tb.getEnd().getOffset();
    byte[] all=new byte[(int)(te-ts+1)]; mem.getBytes(tb.getStart(), all);
    long[] cmps={0x4c1c5cL,0x4c1c7cL};
    Set<Long> hostFns=new LinkedHashSet<Long>();
    for(long t: cmps){
      byte b0=(byte)(t&0xff),b1=(byte)((t>>8)&0xff),b2=(byte)((t>>16)&0xff),b3=(byte)((t>>24)&0xff);
      pw.println("\nrefs to compare fn 0x"+Long.toHexString(t)+":");
      for(int i=0;i+3<all.length;i++){
        if(all[i]==b0&&all[i+1]==b1&&all[i+2]==b2&&all[i+3]==b3){
          long va=ts+i;
          Function f=getFunctionContaining(sp.getAddress(va));
          pw.println(String.format("  ref @0x%08x in %s", va, f!=null?("FUN_"+Long.toHexString(f.getEntryPoint().getOffset())):"?"));
          if(f!=null) hostFns.add(f.getEntryPoint().getOffset());
        }
      }
    }
    pw.println("\nonPreRender host fn(s): "+hostFns);
    for(long fn: hostFns){
      pw.println("\n================ onPreRender FUN_"+Long.toHexString(fn)+" ================");
      pw.println("---- decompile ----");
      pw.println(deco(fn));
      pw.println("---- disasm ----");
      Function f=getFunctionContaining(sp.getAddress(fn));
      if(f!=null) disasm(f.getEntryPoint().getOffset(), f.getBody().getMaxAddress().getOffset());
    }
    // dump everything disassembled in the gap too
    pw.println("\n================ gap functions ================");
    FunctionIterator fit=currentProgram.getFunctionManager().getFunctions(sp.getAddress(gapLo),true);
    while(fit.hasNext()){ Function f=fit.next(); long a=f.getEntryPoint().getOffset(); if(a>=gapHi)break; if(a>=gapLo){
      pw.println("\n--- FUN_"+Long.toHexString(a)+" ---"); pw.println(deco(a)); } }

    pw.close();
    println("wrote re/v7g.txt; hostFns="+hostFns);
  }
}
