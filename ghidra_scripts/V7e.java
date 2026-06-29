// V7e — locate ScoreListCtrl via class-name string "ScoreListCtrl" and FOURCC 'FGsc' (0x63734746).
// The persistent catalog labels a vtable by the name at *(*(vt+0x1c))+0x30 (see FullCatalog). Find the
// vtable whose descriptor names ScoreListCtrl; dump it; force-disassemble + decompile its method slots
// to find onPreRender (m_qsort x2 / tabStops terminator) and onRenderCell.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.app.decompiler.*;
import java.io.*;
import java.util.*;

public class V7e extends GhidraScript {
  PrintWriter pw; DecompInterface di; AddressSpace sp; Memory mem;
  long textMin,textMax;
  long u32(long va) throws Exception { return mem.getInt(sp.getAddress(va)) & 0xffffffffL; }
  boolean inText(long v){ return v>=textMin && v<textMax; }
  String nameAt(long va){
    try{ StringBuilder s=new StringBuilder(); Address a=sp.getAddress(va);
      for(int i=0;i<60;i++){int b=mem.getByte(a.add(i))&0xff; if(b==0)break;
        boolean ok=(b>='A'&&b<='Z')||(b>='a'&&b<='z')||(b>='0'&&b<='9')||b=='_'||b==':'; if(!ok)return null; s.append((char)b);}
      String r=s.toString(); if(r.length()<3)return null; return r;
    }catch(Exception e){return null;}
  }
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
  List<Long> findBytes(byte[] pat) {
    List<Long> hits=new ArrayList<Long>();
    for (MemoryBlock b: mem.getBlocks()){ if(!b.isInitialized())continue;
      try{ byte[] buf=new byte[(int)b.getSize()]; mem.getBytes(b.getStart(),buf);
        for(int i=0;i+pat.length<buf.length;i++){boolean ok=true;
          for(int j=0;j<pat.length;j++) if(buf[i+j]!=pat[j]){ok=false;break;}
          if(ok) hits.add(b.getStart().getOffset()+i);}
      }catch(Exception e){}
    }
    return hits;
  }

  public void run() throws Exception {
    sp = currentProgram.getAddressFactory().getDefaultAddressSpace();
    mem = currentProgram.getMemory();
    di = new DecompInterface(); di.openProgram(currentProgram);
    MemoryBlock tb=mem.getBlock(".text"); textMin=tb.getStart().getOffset(); textMax=tb.getEnd().getOffset();
    pw = new PrintWriter(new BufferedWriter(new FileWriter(
        System.getProperty("user.home")+"/v7e.txt")));

    // 1. find class-name string "ScoreListCtrl"
    List<Long> nameHits = findBytes("ScoreListCtrl".getBytes());
    pw.println("\"ScoreListCtrl\" string @: ");
    for(long h:nameHits) pw.println(String.format("  0x%08x", h));

    // 2. find the vtable whose descriptor names ScoreListCtrl.
    // catalog rule: name = string at *(*(vt+0x1c))+0x30 ... but descriptor layout varies. We instead
    // scan .data/.rdata for a pointer to (nameHit-0x30) i.e. a descriptor record whose +0 or +0x30 ~ name,
    // then find a vtable pointing at that descriptor at +0x1c. Simpler: scan all vtables (V) and test realName.
    pw.println("\n===== scanning for vtable naming ScoreListCtrl =====");
    List<Long> vts=new ArrayList<Long>();
    for (MemoryBlock b: mem.getBlocks()){
      if(!b.isInitialized()||b.getName().equals(".text"))continue;
      long start=b.getStart().getOffset(), end=b.getEnd().getOffset()-0x40;
      for(long V=start; V<=end; V+=4){
        long descr; try{ descr=u32(V+0x1c);}catch(Exception e){continue;}
        // descriptor must point into init mem; name at descr+0x30
        String nm=nameAt(descr+0x30);
        if(nm!=null && nm.equals("ScoreListCtrl")){
          long slot0; try{slot0=u32(V);}catch(Exception e){continue;}
          pw.println(String.format("  vtable candidate V=0x%08x  descr=0x%08x slot0=0x%08x", V, descr, slot0));
          vts.add(V);
        }
      }
    }

    // 3. Also: find FOURCC 'FGsc' = bytes 'F','G','s','c' = 46 47 73 63 (as it'd appear if stored as chars)
    pw.println("\n===== 'FGsc' (46 47 73 63) occurrences =====");
    for(long h: findBytes(new byte[]{0x46,0x47,0x73,0x63})) {
      Function f=getFunctionContaining(sp.getAddress(h));
      pw.println(String.format("  0x%08x  %s", h, f!=null?String.format("FUN_%08x",f.getEntryPoint().getOffset()):"(data)"));
    }

    // 4. For each vtable found, dump slots + decompile class methods (anything in .text), looking for onPreRender/onRenderCell
    for (long vt: vts){
      pw.println("\n========== ScoreListCtrl vtable @0x"+Long.toHexString(vt)+" ==========");
      Set<Long> classFns=new LinkedHashSet<Long>();
      for(long v=vt; v<vt+0x160; v+=4){
        long val; try{val=u32(v);}catch(Exception e){break;}
        if(!inText(val)) continue;
        Function f=getFunctionAt(sp.getAddress(val));
        if(f==null){ try{disassemble(sp.getAddress(val)); f=createFunction(sp.getAddress(val),null);}catch(Exception e){} }
        pw.println(String.format("  [0x%08x] = 0x%08x %s", v, val, f!=null?f.getName():"?"));
        classFns.add(val);
      }
      // decompile each unique slot fn; print those that look like onPreRender / onRenderCell
      for(long c: classFns){
        String d=deco(c);
        // heuristic: onPreRender has multiple qsort-ish/string scan; onRenderCell big with drawText.
        pw.println("\n  ----- FUN_"+String.format("%08x",c)+" -----");
        pw.println(d);
      }
    }
    pw.close();
    println("wrote re/v7e.txt; nameHits="+nameHits.size()+" vtables="+vts);
  }
}
