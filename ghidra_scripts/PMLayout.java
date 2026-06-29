// PMLayout — pin the clientFreeList member offset for 1.40.655.
//  getFreeId() { return clientFreeList[0].id; } is the LAST virtual in PlayerManager's vtable (playerManager.h).
//  Dump the FULL PlayerManager vtable (0x65d3fc) until it leaves .text; decompile the last ~8 slots so we can
//  read getFreeId = `return *(int*)*(this + OFF);` -> OFF is the clientFreeList byte offset.
//  Also decompile the ctor FUN_004b8f60 (full body) + reset/findClient to cross-check sizeof(ClientRep)=0x1e8,
//  the clientList base offset (0x60 from SimObject base), MaxTeams, and the free-list head member offset.
// Writes re/pm_layout.txt + prints summary.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.*;
import ghidra.app.decompiler.*;
import java.io.*;
import java.util.*;

public class PMLayout extends GhidraScript {
  Memory mem; AddressSpace sp; FunctionManager fm; SymbolTable st; DecompInterface di;
  long textMin, textMax;
  PrintWriter pw;
  static final long PM_VTBL = 0x65d3fcL;

  long u32(long va) throws Exception { return mem.getInt(sp.getAddress(va)) & 0xffffffffL; }
  boolean inText(long v){ return v>=textMin && v<textMax; }
  void out(String s){ println(s); pw.println(s); }
  String fnName(long fa){ Function f=fm.getFunctionContaining(sp.getAddress(fa)); if(f!=null)return f.getName(true); Symbol s=st.getPrimarySymbol(sp.getAddress(fa)); return s!=null?s.getName(true):"?"; }
  Function funcAt(long ea){ Address a=sp.getAddress(ea); Function f=fm.getFunctionAt(a); if(f==null)f=fm.getFunctionContaining(a); if(f==null){try{disassemble(a);f=createFunction(a,null);}catch(Exception e){}} return f; }
  String deco(long ea){ Function f=funcAt(ea); if(f==null)return "  <no func>"; DecompileResults r=di.decompileFunction(f,90,monitor); return (r!=null&&r.decompileCompleted())?r.getDecompiledFunction().getC():"  <fail>"; }

  public void run() throws Exception {
    mem=currentProgram.getMemory(); sp=currentProgram.getAddressFactory().getDefaultAddressSpace();
    fm=currentProgram.getFunctionManager(); st=currentProgram.getSymbolTable();
    di=new DecompInterface(); di.openProgram(currentProgram);
    MemoryBlock tb=mem.getBlock(".text"); textMin=tb.getStart().getOffset(); textMax=tb.getEnd().getOffset();
    pw=new PrintWriter(new BufferedWriter(new FileWriter(
       System.getProperty("user.home")+"/pm_layout.txt")));

    // full vtable
    out("=== PlayerManager FULL vtable @0x65d3fc ===");
    List<Long> slots=new ArrayList<Long>();
    for(int i=0;i<200;i++){
      long s; try{ s=u32(PM_VTBL+i*4L);}catch(Exception e){ break; }
      if(!inText(s)){ out(String.format("   [%2d] +0x%03x -> 0x%08x  <END (not .text)>", i, i*4, s)); break; }
      slots.add(s);
      out(String.format("   [%2d] +0x%03x -> 0x%08x  %s", i, i*4, s, fnName(s)));
    }
    out("vtable length: "+slots.size()+" slots");

    // decompile last 8 slots (getFreeId family) + a few known getters
    out("\n=== last 10 vtable methods (getFreeId is the last; getters reveal member offsets) ===");
    int from=Math.max(0, slots.size()-10);
    for(int i=from;i<slots.size();i++){
      long fa=slots.get(i);
      out("\n---- slot["+i+"] +0x"+Long.toHexString(i*4)+" 0x"+Long.toHexString(fa)+"  "+fnName(fa)+" ----");
      out(deco(fa));
      monitor.checkCancelled();
    }

    // ctor full body (free list build)
    out("\n=== ctor FUN_004b8f60 (full) ===");
    out(deco(0x4b8f60L));

    pw.close();
    println("vtable slots="+slots.size()+"  last slot=0x"+Long.toHexString(slots.get(slots.size()-1))+" -> re/pm_layout.txt");
  }
}
