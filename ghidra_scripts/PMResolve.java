// PMResolve — resolve the 1.40.655 PlayerManager global pointer + clientFreeList offset.
//  PlayerManager vtable = 0x65d3fc (from full_catalog_140.txt).
//  (1) Find every instruction that references the constant 0x65d3fc (vtable write = ctor) and
//      0x6A842C (the OLD Borland global pointer the Kronos plugin used). Decompile the ctor.
//  (2) Decompile the PlayerManager vtable tail slots (findTeam/findClient/findBaseRep region) which
//      walk clientList[]/clientFreeList — these reveal sizeof(ClientRep), MaxClients, MaxTeams,
//      sizeof(TeamRep), and the clientFreeList member offset.
//  (3) Scan for a global DWORD that a PlayerManager instance is stored into (singleton pointer):
//      decompile functions that read such a global and use vtable 0x65d3fc / call PlayerManager methods.
// Writes re/pm_resolve.txt and prints a summary.
// Run: analyzeHeadless re\proj tribes -process Tribes.exe -noanalysis -scriptPath re\ghidra_scripts -postScript PMResolve.java
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.scalar.*;
import ghidra.app.decompiler.*;
import java.io.*;
import java.util.*;

public class PMResolve extends GhidraScript {
  Memory mem; AddressSpace sp; FunctionManager fm; SymbolTable st; DecompInterface di; Listing lst;
  long textMin, textMax, dataMin, dataMax;
  PrintWriter pw;
  static final long PM_VTBL = 0x65d3fcL;
  static final long OLD_GLOBAL = 0x6A842CL;

  long u32(long va) throws Exception { return mem.getInt(sp.getAddress(va)) & 0xffffffffL; }
  boolean inText(long v){ return v>=textMin && v<textMax; }
  boolean inData(long v){ return v>=dataMin && v<dataMax; }
  void out(String s){ println(s); pw.println(s); }

  String fnName(long fa){
    Address a=sp.getAddress(fa);
    Function f=fm.getFunctionContaining(a);
    if(f!=null) return f.getName(true)+(f.getEntryPoint().getOffset()==fa?"":"+0x"+Long.toHexString(fa-f.getEntryPoint().getOffset()));
    Symbol s=st.getPrimarySymbol(a);
    return s!=null? s.getName(true) : "?";
  }

  Function funcAt(long ea){
    Address a=sp.getAddress(ea);
    Function f=fm.getFunctionAt(a); if(f==null)f=fm.getFunctionContaining(a);
    if(f==null){ try{disassemble(a); f=createFunction(a,null);}catch(Exception e){} }
    return f;
  }
  String deco(long ea){
    Function f=funcAt(ea);
    if(f==null) return "  <no func @0x"+Long.toHexString(ea)+">";
    DecompileResults r=di.decompileFunction(f,90,monitor);
    return (r!=null&&r.decompileCompleted())? r.getDecompiledFunction().getC() : "  <fail @0x"+Long.toHexString(ea)+">";
  }

  // collect every instruction whose scalar operand or address operand == target constant
  List<Address> refsToConst(long target) throws Exception {
    List<Address> hits=new ArrayList<Address>();
    InstructionIterator ii=lst.getInstructions(true);
    while(ii.hasNext()){
      Instruction in=ii.next();
      int n=in.getNumOperands();
      for(int op=0; op<n; op++){
        // scalar operand?
        Object[] objs=in.getOpObjects(op);
        for(Object o: objs){
          if(o instanceof Scalar){
            long v=((Scalar)o).getUnsignedValue();
            if(v==target){ hits.add(in.getAddress()); break; }
          } else if(o instanceof Address){
            if(((Address)o).getOffset()==target){ hits.add(in.getAddress()); break; }
          }
        }
      }
    }
    return hits;
  }

  public void run() throws Exception {
    mem=currentProgram.getMemory(); sp=currentProgram.getAddressFactory().getDefaultAddressSpace();
    fm=currentProgram.getFunctionManager(); st=currentProgram.getSymbolTable(); lst=currentProgram.getListing();
    di=new DecompInterface(); di.openProgram(currentProgram);
    MemoryBlock tb=mem.getBlock(".text"); textMin=tb.getStart().getOffset(); textMax=tb.getEnd().getOffset();
    MemoryBlock db=mem.getBlock(".data"); dataMin=db.getStart().getOffset(); dataMax=db.getEnd().getOffset();
    pw=new PrintWriter(new BufferedWriter(new FileWriter(
       "C:\\Users\\Joe\\Desktop\\Tribes Browser Based\\re\\pm_resolve.txt")));
    out("PlayerManager resolve — vtable=0x"+Long.toHexString(PM_VTBL)+"  .data=["+Long.toHexString(dataMin)+".."+Long.toHexString(dataMax)+")");

    // --- (0) what's at the OLD global 0x6A842C ---
    out("\n=== OLD global 0x6A842C ===");
    out("  in .data? "+inData(OLD_GLOBAL));
    try{ long v=u32(OLD_GLOBAL); out("  *(0x6A842C) = 0x"+Long.toHexString(v)+"  (in .text? "+inText(v)+", in .data? "+inData(v)+")"); }catch(Exception e){ out("  unreadable"); }
    List<Address> oldRefs=refsToConst(OLD_GLOBAL);
    out("  refs to 0x6A842C: "+oldRefs.size());
    for(Address a: oldRefs){ if(oldRefs.indexOf(a)<20) out("    "+a+"  in "+fnName(a.getOffset())); }

    // --- (1) refs to the vtable constant 0x65d3fc => the ctor (writes it to [this]) ---
    out("\n=== refs to PlayerManager vtable 0x65d3fc ===");
    List<Address> vtRefs=refsToConst(PM_VTBL);
    out("  count: "+vtRefs.size());
    Set<Function> ctorCandidates=new LinkedHashSet<Function>();
    for(Address a: vtRefs){
      Function f=fm.getFunctionContaining(a);
      out("    "+a+"  in "+(f!=null?f.getName(true)+" @"+f.getEntryPoint():"?"));
      if(f!=null) ctorCandidates.add(f);
    }

    // --- (2) decompile the ctor(s) — they init clientFreeList + show array sizes ---
    out("\n=== ctor / vtable-writer decompiles ===");
    for(Function f: ctorCandidates){
      long ea=f.getEntryPoint().getOffset();
      out("\n---- "+f.getName(true)+" @0x"+Long.toHexString(ea)+" ----");
      out(deco(ea));
      monitor.checkCancelled();
    }

    // --- (3) decompile vtable tail slots that touch the free list / client array ---
    // From probe140 the PM vtable is large; findTeam/findClient/findBaseRep sit in the tail.
    // Dump slots 0x40..0x120 names, then decompile the ones whose names look unique (per-class).
    out("\n=== PlayerManager vtable slots (find the client/team walkers) ===");
    List<Long> tailFns=new ArrayList<Long>();
    for(int i=0;i<90;i++){
      long slot; try{ slot=u32(PM_VTBL+i*4L);}catch(Exception ex){ break; }
      if(!inText(slot)){ if(i>6) break; else continue; }
      out(String.format("   [%2d] +0x%03x -> 0x%08x  %s", i, i*4, slot, fnName(slot)));
      tailFns.add(slot);
    }

    // decompile the LAST ~14 slots (findTeam/findClient/findBaseRep/getSkin region) to read offsets
    out("\n=== decompile tail vtable methods (offset evidence) ===");
    int from=Math.max(0, tailFns.size()-16);
    Set<Long> seen=new HashSet<Long>();
    for(int i=from;i<tailFns.size();i++){
      long fa=tailFns.get(i);
      if(seen.contains(fa)) continue; seen.add(fa);
      out("\n---- slot["+i+"] 0x"+Long.toHexString(fa)+"  "+fnName(fa)+" ----");
      out(deco(fa));
      monitor.checkCancelled();
    }

    // --- (4) hunt the singleton global: a .data DWORD that holds a PlayerManager* ---
    // Heuristic: find functions that compare/store an object with vtable 0x65d3fc against a .data global.
    // Practical route: list .data dwords currently equal to 0 won't help statically; instead, scan
    // every instruction "mov [abs], reg" where the same function earlier referenced 0x65d3fc-built obj.
    // Simpler+robust: report any .data pointer that EQUALS a known PlayerManager (none at static rest),
    // and rely on ctor decompile + sg.manager fallback. We additionally list ALL data globals
    // referenced inside the ctor's caller for manual read.
    out("\n=== singleton-global search: callers of the ctor ===");
    if(!ctorCandidates.isEmpty()){
      Function ctor=ctorCandidates.iterator().next();
      ReferenceManager rm=currentProgram.getReferenceManager();
      ReferenceIterator ri=rm.getReferencesTo(ctor.getEntryPoint());
      int cc=0;
      while(ri.hasNext() && cc<12){
        Reference r=ri.next();
        Address from2=r.getFromAddress();
        Function cf=fm.getFunctionContaining(from2);
        out("\n  caller @"+from2+"  in "+(cf!=null?cf.getName(true)+" @"+cf.getEntryPoint():"?"));
        if(cf!=null){ out(deco(cf.getEntryPoint().getOffset())); }
        cc++;
        monitor.checkCancelled();
      }
    } else out("  (no ctor candidate found via vtable const)");

    pw.close();
    println("\n=== SUMMARY ===");
    println("vtable refs (ctor sites): "+vtRefs.size()+"  | old-global refs: "+oldRefs.size());
    println("Wrote re\\pm_resolve.txt");
  }
}
