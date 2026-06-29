// PMFree — nail the clientFreeList member offset + SimObject base + free-list builder for 1.40.655.
//  Decompile the helpers referenced in PlayerManager::processEvent:
//    findClient  = FUN_004b65d0   findBaseRep = FUN_004b6610   removeClient = FUN_004b7b30
//    addBaseRep? = FUN_004b65d0 ... and the free-list RESET/INIT builder.
//  Also: getFreeId() returns clientFreeList[0].id — find a tiny function that does
//    `return *(int*)*(int*)(this + OFF)` (single deref of a member, member is a ClientRep*).
//  And decompile clientAdded/reset which POP from clientFreeList (the inverse of ctor's push).
//  Strategy to find the freelist offset robustly: decompile every PlayerManager method that
//  references the singleton DAT_006d5054 / DAT_006d4fdc OR is xref'd from them, plus the named helpers.
// Writes re/pm_free.txt.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.*;
import ghidra.app.decompiler.*;
import java.io.*;
import java.util.*;

public class PMFree extends GhidraScript {
  Memory mem; AddressSpace sp; FunctionManager fm; SymbolTable st; DecompInterface di;
  long textMin, textMax;
  PrintWriter pw;
  void out(String s){ println(s); pw.println(s); }
  Function funcAt(long ea){ Address a=sp.getAddress(ea); Function f=fm.getFunctionAt(a); if(f==null)f=fm.getFunctionContaining(a); if(f==null){try{disassemble(a);f=createFunction(a,null);}catch(Exception e){}} return f; }
  String deco(long ea){ Function f=funcAt(ea); if(f==null)return "  <no func @0x"+Long.toHexString(ea)+">"; DecompileResults r=di.decompileFunction(f,120,monitor); return (r!=null&&r.decompileCompleted())?r.getDecompiledFunction().getC():"  <fail @0x"+Long.toHexString(ea)+">"; }
  String nm(long ea){ Function f=fm.getFunctionContaining(sp.getAddress(ea)); return f!=null?f.getName(true)+" @"+f.getEntryPoint():"?"; }

  public void run() throws Exception {
    mem=currentProgram.getMemory(); sp=currentProgram.getAddressFactory().getDefaultAddressSpace();
    fm=currentProgram.getFunctionManager(); st=currentProgram.getSymbolTable();
    di=new DecompInterface(); di.openProgram(currentProgram);
    MemoryBlock tb=mem.getBlock(".text"); textMin=tb.getStart().getOffset(); textMax=tb.getEnd().getOffset();
    pw=new PrintWriter(new BufferedWriter(new FileWriter(
       "C:\\Users\\Joe\\Desktop\\Tribes Browser Based\\re\\pm_free.txt")));

    // named helpers from processEvent
    long[] helpers = { 0x4b65d0L, 0x4b6610L, 0x4b7b30L, 0x4b6e40L, 0x4b5190L, 0x4b65d0L, 0x4b8ec0L };
    String[] hn = { "FUN_004b65d0 (findClient?)","FUN_004b6610 (findBaseRep?)","FUN_004b7b30 (removeClient?)",
                    "FUN_004b6e40 (?)","FUN_004b5190 (findTeam?)","dup","FUN_004b8ec0 (ctor-helper free-list build?)" };
    LinkedHashSet<Long> done=new LinkedHashSet<Long>();
    for(int i=0;i<helpers.length;i++){
      if(done.contains(helpers[i])) continue; done.add(helpers[i]);
      out("\n======== "+hn[i]+"  ("+nm(helpers[i])+") ========");
      out(deco(helpers[i]));
      monitor.checkCancelled();
    }

    // Find functions referencing the SERVER singleton DAT_006d5054 (reads of the PlayerManager*)
    out("\n\n################ readers of server singleton 0x6D5054 ################");
    dumpRefsToData(0x6d5054L, 14);
    out("\n\n################ readers of client singleton 0x6D4FDC ################");
    dumpRefsToData(0x6d4fdcL, 6);

    pw.close();
    println("Wrote re/pm_free.txt");
  }

  void dumpRefsToData(long dataAddr, int max) throws Exception {
    ReferenceManager rm=currentProgram.getReferenceManager();
    ReferenceIterator ri=rm.getReferencesTo(sp.getAddress(dataAddr));
    LinkedHashSet<Function> fns=new LinkedHashSet<Function>();
    while(ri.hasNext()){
      Reference r=ri.next();
      Function f=fm.getFunctionContaining(r.getFromAddress());
      if(f!=null) fns.add(f);
    }
    out("  referencing functions: "+fns.size());
    int c=0;
    for(Function f: fns){
      if(c++>=max) break;
      out("\n---- "+f.getName(true)+" @"+f.getEntryPoint()+" ----");
      out(deco(f.getEntryPoint().getOffset()));
      monitor.checkCancelled();
    }
  }
}
