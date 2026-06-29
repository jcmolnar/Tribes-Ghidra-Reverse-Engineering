// T1Hunt — locate T1Vista crash sites:
//  (A) GuardScan Persistent::create (FUN_0058afe4) callers -> the unguarded RemoteCreate deref (vector 2)
//  (B) find resolveGhost: small fns returning *(*(this+0x70)+idx*0x20) (ghost-slot accessor, vectors 3-5)
//  (C) find createDataBlock: a switch-heavy fn with many operator_new (vector 1)
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.app.decompiler.*;
import java.io.*;
import java.util.*;

public class T1Hunt extends GhidraScript {
  public void run() throws Exception {
    AddressSpace sp=currentProgram.getAddressFactory().getDefaultAddressSpace();
    Listing lst=currentProgram.getListing();
    FunctionManager fm=currentProgram.getFunctionManager();
    ReferenceManager rm=currentProgram.getReferenceManager();
    DecompInterface di=new DecompInterface(); di.openProgram(currentProgram);
    PrintWriter pw=new PrintWriter(new BufferedWriter(new FileWriter(
      System.getProperty("user.home")+"/t1hunt.txt")));

    // (A) Persistent::create callers + guard status
    pw.println("===== (A) Persistent::create = FUN_0058afe4 callers =====");
    Address ta=sp.getAddress(0x58afe4L);
    ReferenceIterator it=rm.getReferencesTo(ta); List<Address> callers=new ArrayList<>();
    while(it.hasNext()){ Reference r=it.next(); if(r.getReferenceType().isCall()) callers.add(r.getFromAddress()); }
    Collections.sort(callers);
    for(Address ca:callers){
      Function cf=fm.getFunctionContaining(ca); Address cur=ca; boolean guard=false,deref=false; Address da=null;
      StringBuilder ctx=new StringBuilder();
      for(int i=0;i<12;i++){ Instruction ins=lst.getInstructionAt(cur); if(ins==null) break; String s=ins.toString();
        if(i>0){ if(s.startsWith("TEST EAX")||s.startsWith("CMP EAX")||(s.startsWith("CMP")&&s.contains("EAX"))) guard=true;
          if(!guard&&!deref&&s.startsWith("MOV")&&s.contains("[E")&&!s.contains(",E")&&s.matches(".*\\[E..\\].*")){deref=true;da=cur;} }
        ctx.append(String.format("    0x%08x  %s%n",cur.getOffset(),s)); cur=cur.add(ins.getLength());
        if(ins.getFlowType().isTerminal()) break; }
      pw.println("  caller 0x"+Long.toHexString(ca.getOffset())+(cf!=null?" in "+cf.getName()+" @0x"+Long.toHexString(cf.getEntryPoint().getOffset()):"")
                 +" -> "+(deref&&!guard?"*** UNGUARDED (deref @0x"+(da!=null?Long.toHexString(da.getOffset()):"?")+") ***":guard?"guarded":"no-deref"));
      if(deref&&!guard) pw.print(ctx.toString());
    }

    // (B) resolveGhost candidates: small fns, decompile mentions "+ 0x70)" and "* 0x20"
    pw.println("\n===== (B) resolveGhost candidates (small fn, *(this+0x70)+idx*0x20) =====");
    int b=0;
    for(Function f: fm.getFunctions(true)){
      long n=f.getBody().getNumAddresses(); if(n<8||n>70) continue;
      DecompileResults r=di.decompileFunction(f,25,monitor); if(r==null||!r.decompileCompleted()) continue;
      String c=r.getDecompiledFunction().getC();
      if((c.contains("+ 0x70)")||c.contains("+ 0x80)"))&&c.contains("* 0x20")&&c.contains("return")&&b<6){
        pw.println("  cand "+f.getName()+" @0x"+Long.toHexString(f.getEntryPoint().getOffset())+":");
        for(String ln:c.split("\n")) if(ln.contains("return")||ln.contains("0x20")) pw.println("      "+ln.trim());
        b++;
      }
    }
    pw.close(); println("wrote re/t1hunt.txt");
  }
}
