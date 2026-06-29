// Cat140 — Tribes 1.40.655 catalog: full RTTI class inventory + decompiled unpack/pack for every SimEvent.
// SimEvent family identified structurally: vtable slot4==0x413460 && slot5==0x413470 (the Persistent base
// disk read/write stubs that only the SimEvent layout carries). For those, slot6=pack, slot7=unpack.
// Output: re/full_catalog_140.txt
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.*;
import ghidra.app.decompiler.*;
import java.io.*;
import java.util.*;

public class Cat140 extends GhidraScript {
  Memory mem; AddressSpace sp; FunctionManager fm; SymbolTable st; DecompInterface di;
  long textMin, textMax;
  long u32(long va) throws Exception { return mem.getInt(sp.getAddress(va)) & 0xffffffffL; }
  boolean inText(long v){ return v>=textMin && v<textMax; }
  String deco(long ea){
    Address a=sp.getAddress(ea); Function f=fm.getFunctionAt(a); if(f==null)f=fm.getFunctionContaining(a);
    if(f==null){ try{disassemble(a); f=createFunction(a,null);}catch(Exception e){} }
    if(f==null) return "  <no func @0x"+Long.toHexString(ea)+">";
    DecompileResults r=di.decompileFunction(f,60,monitor);
    return (r!=null&&r.decompileCompleted())? r.getDecompiledFunction().getC() : "  <fail @0x"+Long.toHexString(ea)+">";
  }

  static class C { String name; long vt; boolean isEvent; long pack,unpack; }

  public void run() throws Exception {
    mem=currentProgram.getMemory(); sp=currentProgram.getAddressFactory().getDefaultAddressSpace();
    fm=currentProgram.getFunctionManager(); st=currentProgram.getSymbolTable();
    di=new DecompInterface(); di.openProgram(currentProgram);
    MemoryBlock tb=mem.getBlock(".text"); textMin=tb.getStart().getOffset(); textMax=tb.getEnd().getOffset();

    // class name -> vtable addr (skip _meta_ptr registration vtables)
    Map<String,Long> cls=new TreeMap<String,Long>();
    SymbolIterator it=st.getAllSymbols(true);
    while(it.hasNext()){
      Symbol s=it.next(); String n=s.getName(true);
      if(!n.contains("vftable")) continue;
      if(n.contains("_meta_ptr")) continue;
      String c=n.replace("::vftable","").replace("`vftable'","").trim();
      if(c.isEmpty()) continue;
      if(!cls.containsKey(c)) cls.put(c, s.getAddress().getOffset());
    }

    List<C> events=new ArrayList<C>();
    for(Map.Entry<String,Long> e: cls.entrySet()){
      long vt=e.getValue();
      try{
        long s4=u32(vt+0x10), s5=u32(vt+0x14);
        if(s4==0x413460L && s5==0x413470L){
          C c=new C(); c.name=e.getKey(); c.vt=vt; c.isEvent=true;
          c.pack=u32(vt+0x18); c.unpack=u32(vt+0x1c);
          if(inText(c.pack)&&inText(c.unpack)) events.add(c);
        }
      }catch(Exception ex){}
    }

    PrintWriter pw=new PrintWriter(new BufferedWriter(new FileWriter(
       System.getProperty("user.home")+"/full_catalog_140.txt")));
    pw.println("TRIBES 1.40.655 (Tribes.exe, MSVC2005) — RTTI class catalog + SimEvent wire formats");
    pw.println("Legend: readInt=FUN_0040fd10(bits)  writeInt=FUN_0040fd50(val,bits)");
    pw.println("  BitStream/StreamIO vtbl: +0x18 write(nbytes,&src)  +0x1c read(nbytes,&dst)  +0x28 readString(&dst)  +0x2c writeString(&src,max)");
    pw.println("  SimEvent vtable: slot6(+0x18)=pack  slot7(+0x1c)=unpack ; verifyNotServer guard = FUN_00517200");
    pw.println("Total RTTI classes: "+cls.size()+" ; SimEvent-family: "+events.size()+"\n");

    pw.println("################ SIMEVENT WIRE FORMATS ("+events.size()+") ################");
    for(C c: events){
      pw.println("\n======== "+c.name+"  vtbl=0x"+Long.toHexString(c.vt)
                 +"  pack=0x"+Long.toHexString(c.pack)+"  unpack=0x"+Long.toHexString(c.unpack)+" ========");
      pw.println("---- unpack ----");
      pw.println(deco(c.unpack));
      monitor.checkCancelled();
    }

    // DataBlockEvent::unpack reveals the datablock-unpack vtable slot; dump it explicitly if present.
    Long dbe=cls.get("DataBlockEvent");
    if(dbe!=null){
      pw.println("\n################ DataBlockEvent (locate datablock unpack slot) ################");
      pw.println("vtbl=0x"+Long.toHexString(dbe));
    }

    pw.println("\n\n################ FULL CLASS INVENTORY ("+cls.size()+") ################");
    for(Map.Entry<String,Long> e: cls.entrySet())
      pw.println(String.format("0x%08x  %s", e.getValue(), e.getKey()));
    pw.close();

    println("events="+events.size()+" classes="+cls.size()+" -> re/full_catalog_140.txt");
    // also echo the event names so we see them in the console
    StringBuilder sb=new StringBuilder();
    for(C c: events) sb.append(c.name).append("  ");
    println("EVENTS: "+sb.toString());
  }
}
