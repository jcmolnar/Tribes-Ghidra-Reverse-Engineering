// Probe140 — orient on the MSVC-RTTI Tribes.exe (1.40.655).
//  1) count + sample RTTI vftable symbols (Ghidra's PE RTTI analyzer names them <Class>::vftable).
//  2) for a few known networked classes, dump the first 40 vtable slots (fn addr + Ghidra name) so we can
//     read off which slot is pack/unpack by eye.
//  3) decompile Persistent::create @ 0x4131E0 (the tag -> factory dispatcher).
// Run: analyzeHeadless re\proj tribes -process Tribes.exe -noanalysis -scriptPath re\ghidra_scripts -postScript Probe140.java
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.*;
import ghidra.app.decompiler.*;
import java.io.*;
import java.util.*;

public class Probe140 extends GhidraScript {
  Memory mem; AddressSpace sp; FunctionManager fm; SymbolTable st; DecompInterface di;
  long textMin, textMax;
  PrintWriter pw;
  long u32(long va) throws Exception { return mem.getInt(sp.getAddress(va)) & 0xffffffffL; }
  boolean inText(long v){ return v>=textMin && v<textMax; }
  void out(String s){ println(s); pw.println(s); }

  String fnName(long fa){
    Address a=sp.getAddress(fa);
    Function f=fm.getFunctionAt(a);
    if(f!=null) return f.getName(true);
    Symbol s=st.getPrimarySymbol(a);
    return s!=null? s.getName(true) : "";
  }

  public void run() throws Exception {
    mem=currentProgram.getMemory(); sp=currentProgram.getAddressFactory().getDefaultAddressSpace();
    fm=currentProgram.getFunctionManager(); st=currentProgram.getSymbolTable();
    di=new DecompInterface(); di.openProgram(currentProgram);
    MemoryBlock tb=mem.getBlock(".text"); textMin=tb.getStart().getOffset(); textMax=tb.getEnd().getOffset();
    pw=new PrintWriter(new BufferedWriter(new FileWriter("C:\\Users\\Joe\\Desktop\\Tribes Browser Based\\re\\probe140.txt")));

    // 1) vftable inventory
    List<Symbol> vfs=new ArrayList<Symbol>();
    Map<String,Long> byClass=new TreeMap<String,Long>();
    SymbolIterator it=st.getAllSymbols(true);
    while(it.hasNext()){
      Symbol s=it.next();
      String n=s.getName(true);
      if(n.contains("vftable")){
        vfs.add(s);
        String cls=n.replace("::vftable","").replace("`vftable'","");
        if(!byClass.containsKey(cls)) byClass.put(cls, s.getAddress().getOffset());
      }
    }
    out("=== vftable symbols: "+vfs.size()+" ; distinct class prefixes: "+byClass.size()+" ===");
    int shown=0;
    for(Map.Entry<String,Long> e: byClass.entrySet()){
      if(shown++<60) out(String.format("  %-50s @0x%08x", e.getKey(), e.getValue()));
    }

    // 2) dump known vtables
    String[] targets={"PlayerSayEvent","TeamObjectiveEvent","BulletData","Bullet","PlayerManager","SimObject","Player"};
    for(String t: targets){
      Long vt=null;
      for(Map.Entry<String,Long> e: byClass.entrySet()){
        String k=e.getKey();
        if(k.equals(t)||k.endsWith("::"+t)||k.endsWith(t) && k.replaceAll(".*::","").equals(t)){ vt=e.getValue(); break; }
      }
      if(vt==null){ out("\n-- vtable for "+t+": NOT FOUND --"); continue; }
      out("\n-- vtable "+t+" @0x"+Long.toHexString(vt)+" --");
      for(int i=0;i<40;i++){
        long slot;
        try{ slot=u32(vt+i*4L);}catch(Exception ex){ break; }
        if(!inText(slot)) { if(i>4) break; else continue; }
        out(String.format("   [%2d] +0x%02x -> 0x%08x  %s", i, i*4, slot, fnName(slot)));
      }
    }

    // 3) decompile Persistent::create
    out("\n=== Persistent::create @0x4131E0 ===");
    Address ca=sp.getAddress(0x4131E0L);
    Function cf=fm.getFunctionAt(ca); if(cf==null) cf=fm.getFunctionContaining(ca);
    if(cf==null){ try{ disassemble(ca); cf=createFunction(ca,null);}catch(Exception ex){} }
    if(cf!=null){
      DecompileResults r=di.decompileFunction(cf,60,monitor);
      if(r!=null&&r.decompileCompleted()) out(r.getDecompiledFunction().getC());
      else out("  <decompile failed>");
    } else out("  <no function at 0x4131E0>");

    pw.close();
    println("\nWrote re\\probe140.txt");
  }
}
