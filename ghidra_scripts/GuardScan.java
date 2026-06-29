// GuardScan — Pattern A: for each NULL-returning factory/lookup, list every caller and the
// instructions right after the call, so we can see which deref the result WITHOUT a NULL guard.
// Confirms the target's identity (decompile) + dumps caller context.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.app.decompiler.*;
import java.io.*;
import java.util.*;

public class GuardScan extends GhidraScript {
  public void run() throws Exception {
    AddressSpace sp=currentProgram.getAddressFactory().getDefaultAddressSpace();
    Listing lst=currentProgram.getListing();
    FunctionManager fm=currentProgram.getFunctionManager();
    ReferenceManager rm=currentProgram.getReferenceManager();
    // targets: resolveGhost?(0x517eb0). (add more later: Persistent::create 0x4131e0 etc.)
    long[] targets={0x4131e0L,0x434890L};   // Persistent::create, createDataBlock
    PrintWriter pw=new PrintWriter(new BufferedWriter(new FileWriter(
      System.getProperty("user.home")+"/guardscan.txt")));
    DecompInterface di=new DecompInterface(); di.openProgram(currentProgram);
    for(long t:targets){
      Address ta=sp.getAddress(t);
      Function tf=fm.getFunctionAt(ta);
      pw.println("################ TARGET 0x"+Long.toHexString(t)+(tf!=null?" "+tf.getName():"")+" ################");
      if(tf!=null){
        DecompileResults r=di.decompileFunction(tf,60,monitor);
        if(r!=null&&r.decompileCompleted()){
          String c=r.getDecompiledFunction().getC();
          pw.println("--- decompile (head) ---");
          String[] ls=c.split("\n"); for(int i=0;i<Math.min(ls.length,40);i++) pw.println(ls[i]);
        }
      }
      pw.println("--- callers + post-call context (14 instrs) ---");
      ReferenceIterator it=rm.getReferencesTo(ta);
      List<Address> callers=new ArrayList<>();
      while(it.hasNext()){ Reference rf=it.next(); if(rf.getReferenceType().isCall()) callers.add(rf.getFromAddress()); }
      Collections.sort(callers);
      pw.println("(callers="+callers.size()+"; full context only for UNGUARDED candidates)");
      int nUn=0,nG=0,nNo=0;
      for(Address ca:callers){
        Function cf=fm.getFunctionContaining(ca);
        Address cur=ca; boolean sawGuard=false, sawDeref=false; Address derefAt=null;
        StringBuilder ctx=new StringBuilder();
        for(int i=0;i<14;i++){
          Instruction ins=lst.getInstructionAt(cur);
          if(ins==null) break;
          String s=ins.toString(); String tag="";
          if(i>0){
            if(s.startsWith("TEST EAX,EAX")||s.startsWith("CMP EAX")||s.startsWith("CMP dword ptr [E")&&s.contains("EAX")) { sawGuard=true; tag="  <-- guard"; }
            if((s.startsWith("MOV")||s.contains("CALL dword ptr [EAX")) && s.contains("[EAX") && !sawGuard && !sawDeref){ sawDeref=true; derefAt=cur; tag="  <-- UNGUARDED DEREF of EAX"; }
          }
          ctx.append(String.format("    0x%08x  %-34s%s%n", cur.getOffset(), s, tag));
          cur=cur.add(ins.getLength());
          if(ins.getFlowType().isTerminal()) break;
        }
        if(sawDeref&&!sawGuard){
          nUn++;
          pw.println("\n  *** UNGUARDED caller 0x"+Long.toHexString(ca.getOffset())+(cf!=null?" in "+cf.getName():"")
                     +"  (deref @0x"+Long.toHexString(derefAt.getOffset())+") ***");
          pw.print(ctx.toString());
        } else if(sawGuard) nG++; else nNo++;
      }
      pw.println("\n  SUMMARY: unguarded="+nUn+"  guarded="+nG+"  no-deref-in-window="+nNo);
    }
    pw.close();
    println("wrote re/guardscan.txt");
  }
}
