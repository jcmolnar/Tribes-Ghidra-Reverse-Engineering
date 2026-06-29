// AIInner — decompile the T1Vista inner containment primitive FUN_0058a87c and the crash fn FUN_0043ffbc,
// then enumerate ALL callers of FUN_0058a87c and, for each, dump the decompile so we can spot the structural
// twin of FUN_0043ffbc (two calls to the sub, 2nd on *(this+OBJ)+BOX gated by a flag bit).
// Output: re/ai_inner.txt
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.app.decompiler.*;
import java.io.*;
import java.util.*;

public class AIInner extends GhidraScript {
  DecompInterface di; FunctionManager fm; AddressSpace sp; Listing lst; ReferenceManager rm; PrintWriter pw;

  String dec(Function f){
    DecompileResults r=di.decompileFunction(f,90,monitor);
    return (r!=null&&r.decompileCompleted())? r.getDecompiledFunction().getC() : "  <decompile fail>";
  }

  public void run() throws Exception {
    di=new DecompInterface(); di.openProgram(currentProgram);
    fm=currentProgram.getFunctionManager(); sp=currentProgram.getAddressFactory().getDefaultAddressSpace();
    lst=currentProgram.getListing(); rm=currentProgram.getReferenceManager();
    pw=new PrintWriter(new BufferedWriter(new FileWriter(System.getProperty("user.home")+"/ai_inner.txt")));

    long innerVA = 0x58a87cL;
    long crashFnVA = 0x43ffbcL;

    Function inner = fm.getFunctionContaining(sp.getAddress(innerVA));
    Function crashFn = fm.getFunctionContaining(sp.getAddress(crashFnVA));

    pw.println("############ T1Vista FUN_0043ffbc (the crash fn) ############");
    if(crashFn!=null) pw.println(dec(crashFn)); else pw.println("  <none>");

    pw.println("\n############ T1Vista FUN_0058a87c (the inner primitive) @0x"+Long.toHexString(innerVA)+" ############");
    if(inner!=null){
      pw.println("entry=0x"+Long.toHexString(inner.getEntryPoint().getOffset()));
      pw.println(dec(inner));
    } else pw.println("  <none>");

    // enumerate callers of inner
    if(inner!=null){
      Set<Long> callers=new TreeSet<Long>();
      Address ep=inner.getEntryPoint();
      ReferenceIterator ri=rm.getReferencesTo(ep);
      while(ri.hasNext()){
        Reference ref=ri.next();
        if(!ref.getReferenceType().isCall() && !ref.getReferenceType().isJump()) {
          // still consider — decomp may treat as call
        }
        Function cf=fm.getFunctionContaining(ref.getFromAddress());
        if(cf!=null) callers.add(cf.getEntryPoint().getOffset());
      }
      pw.println("\n############ CALLERS of FUN_0058a87c: "+callers.size()+" ############");
      for(Long cva: callers){
        Function cf=fm.getFunctionAt(sp.getAddress(cva));
        // count call sites to inner inside this caller
        int callsToInner=0; int derefObjBox=0;
        Address a=cf.getEntryPoint(); Address end=cf.getBody().getMaxAddress();
        while(a!=null && a.compareTo(end)<=0){
          Instruction ins=lst.getInstructionAt(a); if(ins==null){a=a.add(1);continue;}
          String op=ins.toString();
          if(op.startsWith("CALL") && op.contains(Long.toHexString(innerVA))) callsToInner++;
          a=ins.getAddress().add(ins.getLength());
        }
        pw.println("\n==== caller 0x"+Long.toHexString(cva)+"  name="+cf.getName()+"  callsToInner="+callsToInner+" ====");
        pw.println(dec(cf));
      }
    }

    pw.close();
    println("wrote re/ai_inner.txt");
  }
}
