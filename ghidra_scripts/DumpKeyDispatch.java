// DumpKeyDispatch — for the identified keyboard->bind dispatch function in the open
// program, print everything Hudbot needs to inline-detour it:
//   - calling convention + parameter storage (where the EVENT ptr arrives: reg or [ESP+n])
//   - the first 24 bytes at the entry (to size the trampoline / relocate for a rel32 jmp)
//   - up to 5 callers, decompiled (to confirm the convention from the call site)
// Target address is picked by program name (the FindKeyDispatch winners):
//   T1Vista.exe -> 0x0050d62c   Tribes.exe -> 0x00526560
// Output: re/keydispatch_abi_<exe>.txt
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.mem.*;
import ghidra.app.decompiler.*;
import java.io.*;
import java.util.*;

public class DumpKeyDispatch extends GhidraScript {
  public void run() throws Exception {
    String prog=currentProgram.getName();
    long target;
    if(prog.equalsIgnoreCase("T1Vista.exe")) target=0x0050d62cL;
    else if(prog.equalsIgnoreCase("Tribes.exe")) target=0x00526560L;
    else { println("DumpKeyDispatch: no target address for "+prog); return; }

    FunctionManager fm=currentProgram.getFunctionManager();
    Memory mem=currentProgram.getMemory();
    Address ta=toAddr(target);
    Function f=fm.getFunctionAt(ta);
    PrintWriter pw=new PrintWriter(new BufferedWriter(new FileWriter(
      System.getProperty("user.home")+"/keydispatch_abi_"+prog+".txt")));

    pw.println("##### "+prog+"  dispatch @0x"+Long.toHexString(target)+" #####");
    if(f==null){ pw.println("  <no function at target>"); pw.close(); println("no fn"); return; }

    pw.println("name: "+f.getName(true));
    pw.println("callingConvention: "+f.getCallingConventionName());
    pw.println("signature: "+f.getSignature().getPrototypeString());
    pw.println("paramCount: "+f.getParameterCount());
    for(Parameter p: f.getParameters())
      pw.println("  param "+p.getOrdinal()+" '"+p.getName()+"' "+p.getDataType().getName()
                 +"  storage="+p.getVariableStorage());
    pw.println("return storage: "+f.getReturn().getVariableStorage());

    // entry bytes (for trampoline sizing / rel32 relocation)
    StringBuilder hb=new StringBuilder();
    for(int i=0;i<24;i++) hb.append(String.format("%02X ", mem.getByte(ta.add(i)) & 0xff));
    pw.println("entry bytes: "+hb.toString().trim());

    // entry instructions (so we know where to cut the trampoline on an instr boundary)
    pw.println("entry disasm:");
    Listing lst=currentProgram.getListing();
    Instruction ins=lst.getInstructionAt(ta);
    int n=0;
    while(ins!=null && n<8){
      pw.println("  0x"+Long.toHexString(ins.getAddress().getOffset())+"  "+ins.toString()
                 +"   ("+ins.getLength()+"b)");
      ins=ins.getNext(); n++;
    }

    // callers (confirm how the event ptr is passed at the call site)
    pw.println("\n##### callers (decompiled) #####");
    DecompInterface di=new DecompInterface(); di.openProgram(currentProgram);
    ReferenceManager rm=currentProgram.getReferenceManager();
    ReferenceIterator ri=rm.getReferencesTo(ta);
    Set<Long> seen=new HashSet<Long>(); int cc=0;
    while(ri.hasNext() && cc<5){
      Reference r=ri.next();
      Function cf=fm.getFunctionContaining(r.getFromAddress());
      if(cf==null) continue;
      long k=cf.getEntryPoint().getOffset();
      pw.println("\n-- caller "+cf.getName(true)+" @0x"+Long.toHexString(k)
                 +"  (ref from 0x"+Long.toHexString(r.getFromAddress().getOffset())
                 +", type="+r.getReferenceType()+") --");
      if(!seen.add(k)){ pw.println("  (dup)"); continue; }
      DecompileResults dr=di.decompileFunction(cf,60,monitor);
      pw.println((dr!=null&&dr.decompileCompleted())? dr.getDecompiledFunction().getC() : "  <fail>");
      cc++;
    }
    // also note vtable refs (virtual dispatch shows as data refs)
    pw.println("\n##### data/xrefs to 0x"+Long.toHexString(target)+" (vtable slots) #####");
    ri=rm.getReferencesTo(ta);
    while(ri.hasNext()){
      Reference r=ri.next();
      if(fm.getFunctionContaining(r.getFromAddress())==null)
        pw.println("  from 0x"+Long.toHexString(r.getFromAddress().getOffset())+"  type="+r.getReferenceType());
    }

    pw.close();
    println("DumpKeyDispatch: wrote re/keydispatch_abi_"+prog+".txt");
  }
}
