// V7c — anchor ScoreListCtrl via "sf_white_10b.pft"/"LowResScore" strings + FOURCC 'FGsc'.
// Find onAdd (refs those strings), its vtable, dump vtable, decompile the class's own methods
// to locate onPreRender (calls m_qsort twice; tabStops terminator) and onRenderCell.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.mem.*;
import ghidra.app.decompiler.*;
import java.io.*;
import java.util.*;

public class V7c extends GhidraScript {
  PrintWriter pw; DecompInterface di; AddressSpace sp; Memory mem;
  long u32(long va) throws Exception { return mem.getInt(sp.getAddress(va)) & 0xffffffffL; }
  String deco(long va) {
    Function f = getFunctionContaining(sp.getAddress(va));
    if (f==null){ try{disassemble(sp.getAddress(va)); f=createFunction(sp.getAddress(va),null);}catch(Exception e){} }
    if (f == null) return "  <no fn @0x"+Long.toHexString(va)+">";
    DecompileResults r = di.decompileFunction(f, 120, monitor);
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
  // find address of an ASCII string in initialized memory
  List<Long> findString(String s) {
    List<Long> hits = new ArrayList<Long>();
    byte[] pat = s.getBytes();
    for (MemoryBlock b : mem.getBlocks()) {
      if (!b.isInitialized()) continue;
      try {
        Address a = b.getStart();
        byte[] buf = new byte[(int)b.getSize()];
        mem.getBytes(a, buf);
        for (int i=0;i+pat.length<buf.length;i++){
          boolean ok=true;
          for (int j=0;j<pat.length;j++) if (buf[i+j]!=pat[j]){ok=false;break;}
          if (ok) hits.add(a.getOffset()+i);
        }
      } catch(Exception e){}
    }
    return hits;
  }
  Set<Long> funcsRefencing(long strAddr) {
    Set<Long> fns = new LinkedHashSet<Long>();
    ReferenceIterator it = currentProgram.getReferenceManager().getReferencesTo(sp.getAddress(strAddr));
    while (it.hasNext()) {
      Reference r = it.next();
      Function f = getFunctionContaining(r.getFromAddress());
      if (f!=null) fns.add(f.getEntryPoint().getOffset());
    }
    return fns;
  }

  public void run() throws Exception {
    sp = currentProgram.getAddressFactory().getDefaultAddressSpace();
    mem = currentProgram.getMemory();
    di = new DecompInterface(); di.openProgram(currentProgram);
    pw = new PrintWriter(new BufferedWriter(new FileWriter(
        System.getProperty("user.home")+"/v7c.txt")));

    String[] anchors = {"sf_white_10b.pft","sf_yellow_10b.pft","LowResScore","sf_white_6.pft"};
    Set<Long> onAddCand = new LinkedHashSet<Long>();
    for (String a : anchors) {
      List<Long> hits = findString(a);
      pw.println("string \""+a+"\" @ "+hits.size()+" locations:");
      for (long h : hits) {
        Set<Long> fns = funcsRefencing(h);
        pw.println(String.format("  0x%08x  refed by %s", h, fns));
        onAddCand.addAll(fns);
      }
    }

    pw.println("\n===== onAdd candidate(s): "+onAddCand+" =====");
    // For each onAdd candidate, decompile + find the vtable pointer it stores (*this = &PTR).
    Set<Long> vtables = new LinkedHashSet<Long>();
    for (long fn : onAddCand) {
      pw.println("\n----- onAdd FUN_"+String.format("%08x",fn)+" -----");
      pw.println(deco(fn));
      // scan its instructions for "MOV [reg], imm32" where imm32 is a .data vtable ptr (0x61xxxx)
      Listing lst = currentProgram.getListing();
      Function f = getFunctionContaining(sp.getAddress(fn));
      if (f==null) continue;
      InstructionIterator it = lst.getInstructions(f.getBody(), true);
      while (it.hasNext()) {
        Instruction ins = it.next();
        String t = ins.toString();
        // look for references to .data in 0x61e000..0x620000 used as a pointer store
        for (Reference r : ins.getReferencesFrom()) {
          long to = r.getToAddress().getOffset();
          if (to>=0x61c000 && to<0x622000) { vtables.add(to); }
        }
      }
    }
    pw.println("\n===== candidate vtables/PTRs referenced by onAdd: "+vtables+" =====");

    // Dump each candidate vtable and decompile its .text slots in 0x488000..0x48b000 (class's own code)
    for (long vt : vtables) {
      pw.println("\n========== vtable @0x"+Long.toHexString(vt)+" ==========");
      Set<Long> classFns = new LinkedHashSet<Long>();
      for (long v = vt; v < vt+0x140; v+=4) {
        long val; try { val=u32(v);}catch(Exception e){break;}
        if (val<0x401000 || val>=0x600000) { if (v>vt+0x10) {} ; continue; }
        Function f = getFunctionAt(sp.getAddress(val));
        String nm=(f!=null)?f.getName():"?";
        pw.println(String.format("  [0x%08x] = 0x%08x %s", v, val, nm));
        if (val>=0x488000 && val<0x48b000) classFns.add(val);
      }
      for (long c : classFns) {
        pw.println("\n  ----- class method FUN_"+String.format("%08x",c)+" -----");
        pw.println(deco(c));
      }
    }
    pw.close();
    println("wrote re/v7c.txt; onAddCand="+onAddCand+" vtables="+vtables);
  }
}
