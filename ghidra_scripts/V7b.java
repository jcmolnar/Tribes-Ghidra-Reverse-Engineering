// V7b — find ScoreListCtrl vtable (contains onWake=0x489d00), dump slots, decompile onPreRender/onRenderCell.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.mem.*;
import ghidra.app.decompiler.*;
import java.io.*;
import java.util.*;

public class V7b extends GhidraScript {
  PrintWriter pw; DecompInterface di; AddressSpace sp; Memory mem;
  long u32(long va) throws Exception { return mem.getInt(sp.getAddress(va)) & 0xffffffffL; }
  String deco(long va) {
    Function f = getFunctionContaining(sp.getAddress(va));
    if (f==null){ try{disassemble(sp.getAddress(va)); f=createFunction(sp.getAddress(va),null);}catch(Exception e){} }
    if (f == null) return "  <no fn @0x"+Long.toHexString(va)+">";
    DecompileResults r = di.decompileFunction(f, 90, monitor);
    return (r!=null && r.decompileCompleted()) ? r.getDecompiledFunction().getC() : "  <decompile fail>";
  }
  void disasmRange(long start, long end) {
    Listing lst = currentProgram.getListing();
    InstructionIterator it = lst.getInstructions(sp.getAddress(start), true);
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
        "C:\\Users\\Joe\\Desktop\\Tribes Browser Based\\re\\v7b.txt")));

    long onWake = 0x489d00L;
    // ---- find data refs (vtable slots) pointing at onWake ----
    pw.println("===== vtable slots referencing onWake 0x489d00 =====");
    ReferenceManager rm = currentProgram.getReferenceManager();
    ReferenceIterator refs = rm.getReferencesTo(sp.getAddress(onWake));
    List<Long> vslots = new ArrayList<Long>();
    while (refs.hasNext()) {
      Reference r = refs.next();
      Address from = r.getFromAddress();
      MemoryBlock b = mem.getBlock(from);
      String bn = b==null?"?":b.getName();
      pw.println(String.format("  ref from 0x%08x  type=%s  block=%s", from.getOffset(), r.getReferenceType(), bn));
      if (b!=null && !bn.equals(".text")) vslots.add(from.getOffset());
    }

    // ---- for each vtable slot, dump surrounding slots ----
    for (long slot : vslots) {
      pw.println("\n===== vtable around slot 0x"+Long.toHexString(slot)+" (onWake) =====");
      // scan back to find vtable start (consecutive .text pointers); just dump -0x40..+0x60
      for (long v = slot-0x40; v <= slot+0x80; v+=4) {
        long val;
        try { val = u32(v); } catch(Exception e){ continue; }
        Function f = getFunctionAt(sp.getAddress(val));
        String nm = (f!=null)?f.getName():"";
        String mark = (v==slot)?"  <== onWake":"";
        boolean inText = val>=0x401000 && val<0x600000;
        pw.println(String.format("  [0x%08x] = 0x%08x %s%s", v, val, inText?nm:"(non-text)", mark));
      }
    }

    // ---- decompile the functions in slots right after onWake (onPreRender/onRenderCell are GUI virtuals) ----
    // Also decompile the immediate-neighbor functions in .text after onWake.
    pw.println("\n\n===== neighbor functions after onWake (likely onPreRender / onRenderCell) =====");
    long[] probes = new long[]{ 0x489e3aL, 0x489d00L };
    // collect candidate function entry points from the vtable slots near onWake (-0x40..+0x80)
    Set<Long> cand = new LinkedHashSet<Long>();
    for (long slot : vslots) {
      for (long v = slot-0x20; v <= slot+0x80; v+=4) {
        long val; try { val=u32(v);}catch(Exception e){continue;}
        if (val>=0x401000 && val<0x600000) cand.add(val);
      }
    }
    for (long c : cand) {
      pw.println("\n----- FUN_"+String.format("%08x",c)+" -----");
      String d = deco(c);
      pw.println(d);
    }
    pw.close();
    println("wrote re/v7b.txt; vslots="+vslots.size()+" cands="+cand.size());
  }
}
