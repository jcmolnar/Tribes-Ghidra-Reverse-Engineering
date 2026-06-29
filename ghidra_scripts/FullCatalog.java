// FULL CATALOG of all 232 persistent classes with CORRECT names + decompiled unpack formats.
// Naming rule (derived empirically): SimEvent-family vtables (slot0 == 0x58b794) have the descriptor LABEL
// SHIFTED by one (descr at V+0x1c names the class at the NEXT vtable), so use the previous SimEvent vtable's
// descriptor: name = string at (*((V-0x34)+0x1c))+0x30. All OTHER families (datablocks/SimObjects) are labeled
// correctly by the naive descr at V+0x1c. pack/unpack addresses are always read straight from the vtable, so
// they're correct regardless. Writes the catalog + every unpack decompile to re/full_catalog.txt.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.app.decompiler.*;
import java.util.*;

public class FullCatalog extends GhidraScript {
  Memory mem; AddressSpace sp; FunctionManager fm; DecompInterface di;
  long textMin, textMax;
  static final long SIMEVENT_SLOT0 = 0x0058b794L;
  long u32(long va) throws MemoryAccessException { return mem.getInt(sp.getAddress(va)) & 0xffffffffL; }
  boolean inText(long v){ return v>=textMin && v<textMax; }
  String nameAt(long va){
    try{ StringBuilder s=new StringBuilder(); Address a=sp.getAddress(va);
      for(int i=0;i<60;i++){int b=mem.getByte(a.add(i))&0xff; if(b==0)break;
        boolean ok=(b>='A'&&b<='Z')||(b>='a'&&b<='z')||(b>='0'&&b<='9')||b=='_'||b==':'; if(!ok)return null; s.append((char)b);}
      String r=s.toString(); if(r.length()<3)return null; char c=r.charAt(0); if(c<'A'||c>'Z')return null; return r;
    }catch(Exception e){return null;}
  }
  String realName(long vt){
    try{
      long s0=u32(vt);
      if(s0==SIMEVENT_SLOT0){               // SimEvent family: label is shifted, use previous vtable's descr
        long prev=vt-0x34;
        if(u32(prev)==SIMEVENT_SLOT0) { String n=nameAt(u32(prev+0x1c)+0x30); if(n!=null) return n; }
        // first in cluster (no SimEvent predecessor) -> fall through to naive
      }
      return nameAt(u32(vt+0x1c)+0x30);      // datablocks/SimObjects: naive is correct
    }catch(Exception e){ return null; }
  }
  String deco(long v){
    Address pa=sp.getAddress(v); Function f=fm.getFunctionAt(pa); if(f==null)f=fm.getFunctionContaining(pa);
    if(f==null){ try{disassemble(pa); f=createFunction(pa,null);}catch(Exception e){} }
    if(f==null) return "  <no func @0x"+Long.toHexString(v)+">";
    DecompileResults r=di.decompileFunction(f,60,monitor);
    return (r!=null&&r.decompileCompleted())? r.getDecompiledFunction().getC() : "  <fail>";
  }
  static class C { long vt,pack,unpack; String name; boolean simEvent; }

  public void run() throws Exception {
    mem=currentProgram.getMemory(); sp=currentProgram.getAddressFactory().getDefaultAddressSpace();
    fm=currentProgram.getFunctionManager(); di=new DecompInterface(); di.openProgram(currentProgram);
    MemoryBlock tb=mem.getBlock(".text"); textMin=tb.getStart().getOffset(); textMax=tb.getEnd().getOffset();

    Map<Long,C> found=new LinkedHashMap<Long,C>();
    Set<String> seen=new HashSet<String>();
    for(MemoryBlock b: mem.getBlocks()){
      if(!b.isInitialized() || b.getName().equals(".text")) continue;
      long start=b.getStart().getOffset(), end=b.getEnd().getOffset()-0x20;
      for(long V=start; V<=end; V+=4){
        long pack,unpack,descr;
        try{ pack=u32(V+0x0c); unpack=u32(V+0x10); descr=u32(V+0x1c);}catch(Exception e){continue;}
        if(!inText(pack)||!inText(unpack)||pack==0||unpack==0) continue;
        if(nameAt(descr+0x30)==null) continue;          // must have a class-name descriptor
        String nm=realName(V);
        if(nm==null || !seen.add(nm)) continue;
        C c=new C(); c.vt=V; c.pack=pack; c.unpack=unpack; c.name=nm;
        try{ c.simEvent=(u32(V)==SIMEVENT_SLOT0);}catch(Exception e){}
        found.put(V,c);
      }
    }
    List<C> all=new ArrayList<C>(found.values());
    Collections.sort(all,new Comparator<C>(){public int compare(C a,C b){return a.name.compareTo(b.name);}});
    println("=== "+all.size()+" persistent classes (corrected names) ===");

    java.io.PrintWriter pw=new java.io.PrintWriter(new java.io.BufferedWriter(new java.io.FileWriter(
       System.getProperty("user.home")+"/full_catalog.txt")));
    pw.println("FULL CATALOG — "+all.size()+" persistent classes in T1Vista.exe, corrected names + unpack formats.");
    pw.println("Naming: SimEvent-family (vtbl slot0=0x58b794) uses V-0x34 shift; others naive. pack/unpack always exact.\n");
    int ev=0,db=0;
    for(C c: all){
      if(c.simEvent) ev++; else db++;
      String line=String.format("%-30s %-9s vtbl=0x%08x pack=0x%08x unpack=0x%08x", c.name, c.simEvent?"[event]":"[obj]", c.vt, c.pack, c.unpack);
      println("  "+line);
      pw.println("\n================================================================");
      pw.println(line);
      pw.println("---- unpack ----");
      pw.println(deco(c.unpack));
      monitor.checkCancelled();
    }
    pw.close();
    println("\n"+ev+" SimEvent-family, "+db+" object/datablock. Wrote re/full_catalog.txt");
  }
}
