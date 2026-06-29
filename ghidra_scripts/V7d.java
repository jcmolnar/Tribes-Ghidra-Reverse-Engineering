// V7d — raw-scan .text for the 4-byte LE address constants of ScoreListCtrl's onAdd strings
// (0x6289f9 LowResScore, 0x628a05 sf_white_6, 0x628a24 sf_white_10b, 0x628a35 sf_yellow_10b),
// locate the containing function (onAdd), disassemble it to read its vtable store, then dump
// that vtable + decompile the class's own methods (onPreRender / onRenderCell).
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.app.decompiler.*;
import java.io.*;
import java.util.*;

public class V7d extends GhidraScript {
  PrintWriter pw; DecompInterface di; AddressSpace sp; Memory mem;
  long u32(long va) throws Exception { return mem.getInt(sp.getAddress(va)) & 0xffffffffL; }
  String deco(long va) {
    Function f = getFunctionContaining(sp.getAddress(va));
    if (f==null){ try{disassemble(sp.getAddress(va)); f=createFunction(sp.getAddress(va),null);}catch(Exception e){} }
    if (f == null) return "  <no fn @0x"+Long.toHexString(va)+">";
    DecompileResults r = di.decompileFunction(f, 120, monitor);
    return (r!=null && r.decompileCompleted()) ? r.getDecompiledFunction().getC() : "  <decompile fail>";
  }
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
    mem = currentProgram.getMemory();
    di = new DecompInterface(); di.openProgram(currentProgram);
    pw = new PrintWriter(new BufferedWriter(new FileWriter(
        "C:\\Users\\Joe\\Desktop\\Tribes Browser Based\\re\\v7d.txt")));

    long[] targets = {0x6289f9L, 0x628a05L, 0x628a24L, 0x628a35L};
    MemoryBlock tb = mem.getBlock(".text");
    long ts=tb.getStart().getOffset(), te=tb.getEnd().getOffset();
    byte[] buf = new byte[(int)(te-ts+1)];
    mem.getBytes(tb.getStart(), buf);

    Set<Long> hostFns = new LinkedHashSet<Long>();
    for (long t : targets) {
      byte b0=(byte)(t&0xff), b1=(byte)((t>>8)&0xff), b2=(byte)((t>>16)&0xff), b3=(byte)((t>>24)&0xff);
      pw.println("scan for addr 0x"+Long.toHexString(t)+":");
      for (int i=0;i+3<buf.length;i++){
        if (buf[i]==b0 && buf[i+1]==b1 && buf[i+2]==b2 && buf[i+3]==b3) {
          long va = ts+i;
          Function f = getFunctionContaining(sp.getAddress(va));
          String fn = f!=null?String.format("FUN_%08x",f.getEntryPoint().getOffset()):"?";
          pw.println(String.format("  @0x%08x in %s", va, fn));
          if (f!=null) hostFns.add(f.getEntryPoint().getOffset());
        }
      }
    }

    pw.println("\n===== onAdd host function(s): "+hostFns+" =====");
    Set<Long> vtables = new LinkedHashSet<Long>();
    for (long fn : hostFns) {
      pw.println("\n----- FUN_"+String.format("%08x",fn)+" (onAdd) decompile -----");
      pw.println(deco(fn));
      // disasm + collect any data ptr stored to *this (look at all 0x61xxxx/0x62xxxx ptr operands that are vtables)
      Function f = getFunctionContaining(sp.getAddress(fn));
      InstructionIterator it = currentProgram.getListing().getInstructions(f.getBody(), true);
      while (it.hasNext()) {
        Instruction ins = it.next();
        // MOV [reg], imm32  with imm pointing into .data vtable area, OR MOV reg, imm then MOV [..],reg
        Object[] ops;
        int n = ins.getNumOperands();
        for (int oi=0; oi<n; oi++) {
          for (Object o : ins.getOpObjects(oi)) {
            if (o instanceof ghidra.program.model.scalar.Scalar) {
              long v = ((ghidra.program.model.scalar.Scalar)o).getUnsignedValue();
              if (v>=0x60c000 && v<0x622000) {
                // is it a vtable? check that *v is in .text
                try { long first=u32(v); if (first>=0x401000 && first<0x600000) vtables.add(v); } catch(Exception e){}
              }
            }
          }
        }
      }
    }
    pw.println("\n===== vtable candidates from onAdd: "+vtables+" =====");
    for (long vt : vtables) {
      pw.println("\n========== vtable @0x"+Long.toHexString(vt)+" ==========");
      Set<Long> classFns = new LinkedHashSet<Long>();
      for (long v = vt; v < vt+0x160; v+=4) {
        long val; try { val=u32(v);}catch(Exception e){break;}
        Function f = (val>=0x401000&&val<0x600000)?getFunctionAt(sp.getAddress(val)):null;
        if (val<0x401000 || val>=0x600000) continue;
        pw.println(String.format("  [0x%08x] = 0x%08x %s", v, val, f!=null?f.getName():"?"));
        if (val>=0x488000 && val<0x48b000) classFns.add(val);
      }
      for (long c : classFns) {
        pw.println("\n  ----- class method FUN_"+String.format("%08x",c)+" -----");
        pw.println(deco(c));
        pw.println("  ---- disasm ----");
        Function f=getFunctionContaining(sp.getAddress(c));
        if (f!=null) disasm(f.getEntryPoint().getOffset(), f.getBody().getMaxAddress().getOffset());
      }
    }
    pw.close();
    println("wrote re/v7d.txt; hostFns="+hostFns+" vtables="+vtables);
  }
}
