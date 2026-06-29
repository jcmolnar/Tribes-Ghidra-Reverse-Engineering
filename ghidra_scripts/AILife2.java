// AILife2 — AIObj vtable + its onRemove/removeThis, and the gamebase owner/control (un)bind path.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.*;
import ghidra.app.decompiler.*;
import java.io.*;
import java.util.*;

public class AILife2 extends GhidraScript {
  PrintWriter pw; DecompInterface di; AddressSpace sp; Memory mem;
  long u32(long va)throws Exception{return mem.getInt(sp.getAddress(va))&0xffffffffL;}
  Set<Long> dumped=new HashSet<Long>();
  Function ensureFn(long va){
    Function f=getFunctionContaining(sp.getAddress(va));
    if(f==null){ try{disassemble(sp.getAddress(va)); createFunction(sp.getAddress(va),null);}catch(Exception e){} f=getFunctionContaining(sp.getAddress(va)); }
    return f;
  }
  void dump(long va,String tag){
    Function f=ensureFn(va);
    if(f==null){ pw.println("  <null fn @0x"+Long.toHexString(va)+" ("+tag+")>"); return; }
    if(!dumped.add(f.getEntryPoint().getOffset())) return;
    DecompileResults r=di.decompileFunction(f,120,monitor);
    pw.println("\n##### "+tag+"  FUN_"+Long.toHexString(f.getEntryPoint().getOffset())+" (size "+f.getBody().getNumAddresses()+") #####");
    pw.println((r!=null&&r.decompileCompleted())?r.getDecompiledFunction().getC():"<fail>");
  }
  public void run() throws Exception {
    sp=currentProgram.getAddressFactory().getDefaultAddressSpace(); mem=currentProgram.getMemory();
    di=new DecompInterface(); di.openProgram(currentProgram);
    pw=new PrintWriter(new BufferedWriter(new FileWriter("C:\\Users\\Joe\\Desktop\\Tribes Browser Based\\re\\ailife2.txt")));

    // 1. find the vtable slot holding AIObj::onAdd 0x43db28, dump the vtable, decompile 0x43xxxx slots
    long onAdd=0x43db28L;
    pw.println("===== AIObj vtable (slots referencing onAdd 0x43db28) =====");
    ReferenceIterator refs=currentProgram.getReferenceManager().getReferencesTo(sp.getAddress(onAdd));
    List<Long> vts=new ArrayList<Long>();
    while(refs.hasNext()){ Reference r=refs.next(); Address from=r.getFromAddress();
      MemoryBlock b=mem.getBlock(from); if(b!=null && !b.getName().equals(".text")){ pw.println("  slot @0x"+Long.toHexString(from.getOffset())+" in "+b.getName()); vts.add(from.getOffset()); } }
    Set<Long> aiMethods=new LinkedHashSet<Long>();
    for(long slot: vts){
      // dump vtable from slot-0x40 .. slot+0x80
      pw.println("  --- vtable around 0x"+Long.toHexString(slot)+" ---");
      for(long v=slot-0x40; v<=slot+0xc0; v+=4){
        long val; try{val=u32(v);}catch(Exception e){continue;}
        if(val<0x401000||val>=0x600000) continue;
        Function f=getFunctionAt(sp.getAddress(val));
        pw.println(String.format("    [0x%08x]=0x%08x %s%s", v,val, f!=null?f.getName():"?", v==slot?"  <== onAdd":""));
        if(val>=0x43c000 && val<0x440000) aiMethods.add(val);
      }
    }
    pw.println("\n===== AIObj-range methods from the vtable =====");
    for(long m: aiMethods) dump(m, "AIObj-method");

    // 2. gamebase owner/control (un)bind: callers of findBaseRep FUN_0040de80 in the 0x4?????? gamebase range
    pw.println("\n\n===== callers of findBaseRep FUN_0040de80 (setOwnerClient / GameBase::onRemove live here) =====");
    ReferenceIterator fr=currentProgram.getReferenceManager().getReferencesTo(sp.getAddress(0x40de80L));
    Set<Long> seen=new LinkedHashSet<Long>();
    while(fr.hasNext()){ Reference r=fr.next(); if(!r.getReferenceType().isCall())continue;
      Function f=getFunctionContaining(r.getFromAddress()); if(f==null)continue;
      long a=f.getEntryPoint().getOffset(); if(seen.add(a)) ; }
    // also callers of findClient (control path) — find findClient first: it's the sibling that checks isClientRep.
    for(long a: seen) dump(a, "findBaseRep-caller");

    pw.close();
    println("wrote re/ailife2.txt; aiMethods="+aiMethods.size()+" fbrCallers="+seen.size());
  }
}
