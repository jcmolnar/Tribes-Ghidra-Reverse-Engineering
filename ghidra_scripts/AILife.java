// AILife — pin the AI lifecycle / repId<->clientId desync in T1Vista.exe.
// Find callers of clientAdded(FUN_0040b788) and clientDropped(FUN_0040c3d8): that yields
// AIObj::onAdd (calls clientAdded with the AIObj as 5th arg, then player->setOwnerClient(repId))
// and AIObj::onRemove (calls clientDropped(repId)). Decompile them + the owned-obj teardown helper
// FUN_004fe858, and follow setOwnerClient.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.app.decompiler.*;
import java.io.*;
import java.util.*;

public class AILife extends GhidraScript {
  PrintWriter pw; DecompInterface di; AddressSpace sp;
  Set<Long> dumped=new HashSet<Long>();
  Function ensureFn(long va){
    Function f=getFunctionContaining(sp.getAddress(va));
    if(f==null){ try{disassemble(sp.getAddress(va)); f=createFunction(sp.getAddress(va),null);}catch(Exception e){} f=getFunctionContaining(sp.getAddress(va)); }
    return f;
  }
  void dump(Function f, String tag){
    if(f==null){ pw.println("  <null fn ("+tag+")>"); return; }
    if(!dumped.add(f.getEntryPoint().getOffset())){ pw.println("  (already dumped FUN_"+Long.toHexString(f.getEntryPoint().getOffset())+")"); return; }
    DecompileResults r=di.decompileFunction(f,120,monitor);
    pw.println("\n##### "+tag+"  FUN_"+Long.toHexString(f.getEntryPoint().getOffset())+" (size "+f.getBody().getNumAddresses()+") #####");
    pw.println((r!=null&&r.decompileCompleted())?r.getDecompiledFunction().getC():"<fail>");
  }
  void disasm(long va){
    Function f=getFunctionContaining(sp.getAddress(va)); if(f==null) return;
    pw.println("  ---- disasm FUN_"+Long.toHexString(f.getEntryPoint().getOffset())+" ----");
    InstructionIterator it=currentProgram.getListing().getInstructions(f.getBody(),true);
    while(it.hasNext()){ Instruction ins=it.next(); StringBuilder b=new StringBuilder();
      try{for(byte x:ins.getBytes())b.append(String.format("%02x ",x&0xff));}catch(Exception e){}
      pw.println(String.format("    0x%08x  %-20s %s",ins.getAddress().getOffset(),b.toString().trim(),ins.toString())); }
  }
  List<Long> callers(long target){
    List<Long> c=new ArrayList<Long>();
    ReferenceIterator it=currentProgram.getReferenceManager().getReferencesTo(sp.getAddress(target));
    while(it.hasNext()){ Reference r=it.next(); if(r.getReferenceType().isCall()){ Function f=getFunctionContaining(r.getFromAddress()); if(f!=null) c.add(f.getEntryPoint().getOffset()); } }
    return c;
  }
  public void run() throws Exception {
    sp=currentProgram.getAddressFactory().getDefaultAddressSpace();
    di=new DecompInterface(); di.openProgram(currentProgram);
    pw=new PrintWriter(new BufferedWriter(new FileWriter(System.getProperty("user.home")+"/ailife.txt")));

    pw.println("================= callers of clientAdded FUN_0040b788 =================");
    for(long c: new LinkedHashSet<Long>(callers(0x40b788L))) dump(ensureFn(c), "clientAdded-caller");

    pw.println("\n\n================= callers of clientDropped FUN_0040c3d8 =================");
    for(long c: new LinkedHashSet<Long>(callers(0x40c3d8L))) dump(ensureFn(c), "clientDropped-caller");

    pw.println("\n\n================= owned-object teardown helper FUN_004fe858 (clientDropped +0x98 branch) =================");
    dump(ensureFn(0x4fe858L), "FUN_004fe858");
    pw.println("\n================= FUN_0040dbfc (clientDropped) + FUN_0040de80 (findBaseRep) =================");
    dump(ensureFn(0x40dbfcL), "FUN_0040dbfc");
    dump(ensureFn(0x40de80L), "findBaseRep?");

    pw.close();
    println("wrote re/ailife.txt");
  }
}
