// CtrlPath — the CONTROL path: setControlClient (sibling of setOwnerClient FUN_00448c3c) + findClient
// (sibling of findBaseRep FUN_0040de80) + PlayerPSC::setControlObject. How a client's PSC acquires a
// control object, and whether a stale/bot object can be acquired by a (re)connecting id.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.scalar.*;
import ghidra.program.model.symbol.*;
import ghidra.app.decompiler.*;
import java.io.*;
import java.util.*;

public class CtrlPath extends GhidraScript {
  PrintWriter pw; DecompInterface di; AddressSpace sp;
  Set<Long> done=new HashSet<Long>();
  void dump(long va,String tag){
    Function f=getFunctionContaining(sp.getAddress(va));
    if(f==null){ try{disassemble(sp.getAddress(va)); f=createFunction(sp.getAddress(va),null);}catch(Exception e){} }
    if(f==null){ pw.println("\n##### "+tag+" <no fn @0x"+Long.toHexString(va)+"> #####"); return; }
    if(!done.add(f.getEntryPoint().getOffset())) return;
    DecompileResults r=di.decompileFunction(f,120,monitor);
    pw.println("\n##### "+tag+"  FUN_"+Long.toHexString(f.getEntryPoint().getOffset())+" (size "+f.getBody().getNumAddresses()+") #####");
    pw.println((r!=null&&r.decompileCompleted())?r.getDecompiledFunction().getC():"<fail>");
  }
  public void run() throws Exception {
    sp=currentProgram.getAddressFactory().getDefaultAddressSpace();
    di=new DecompInterface(); di.openProgram(currentProgram);
    pw=new PrintWriter(new BufferedWriter(new FileWriter(System.getProperty("user.home")+"/ctrlpath.txt")));

    // findClient candidates (near findBaseRep 0x40de80)
    pw.println("================= findClient candidates (near findBaseRep FUN_0040de80) =================");
    for(long a: new long[]{0x40de18L,0x40de38L,0x40deb8L,0x40de80L}) dump(a,"findClient?");

    // gamebase owner/control methods cluster around setOwnerClient FUN_00448c3c
    pw.println("\n\n================= gamebase methods [0x448a00,0x449400] (setControlClient lives here) =================");
    FunctionIterator fit=currentProgram.getFunctionManager().getFunctions(sp.getAddress(0x448a00L),true);
    while(fit.hasNext()){ Function f=fit.next(); long a=f.getEntryPoint().getOffset(); if(a>=0x449400L)break;
      dump(a,"gamebase-method"); }

    pw.close();
    println("wrote re/ctrlpath.txt");
  }
}
