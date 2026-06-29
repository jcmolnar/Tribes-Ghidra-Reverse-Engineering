// Dispatch — find the common caller (dispatcher) of the texture-format converters, which holds the
// texture object (param_2) for every upload. Decompile it + entry bytes. Output: re/dispatch.txt
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.app.decompiler.*;
import java.io.*;
import java.util.*;
public class Dispatch extends GhidraScript {
  public void run() throws Exception {
    AddressSpace sp=currentProgram.getAddressFactory().getDefaultAddressSpace();
    FunctionManager fm=currentProgram.getFunctionManager();
    DecompInterface di=new DecompInterface(); di.openProgram(currentProgram);
    long[] conv={0x5d5164L,0x5d5a3cL,0x5d55c0L,0x5d5e34L,0x5d7148L};
    Map<Long,Integer> callerCount=new LinkedHashMap<Long,Integer>();
    for(long c:conv){
      ReferenceIterator it=currentProgram.getReferenceManager().getReferencesTo(sp.getAddress(c));
      Set<Long> fnsForThis=new HashSet<Long>();
      while(it.hasNext()){ Reference r=it.next(); if(!r.getReferenceType().isCall())continue;
        Function f=fm.getFunctionContaining(r.getFromAddress()); if(f==null)continue;
        fnsForThis.add(f.getEntryPoint().getOffset()); }
      for(long fa:fnsForThis) callerCount.put(fa, callerCount.getOrDefault(fa,0)+1);
    }
    PrintWriter pw=new PrintWriter(new BufferedWriter(new FileWriter(System.getProperty("user.home")+"/dispatch.txt")));
    pw.println("caller -> how many of the converters it calls:");
    for(Map.Entry<Long,Integer> e:callerCount.entrySet()) pw.println("  FUN_"+Long.toHexString(e.getKey())+" : "+e.getValue());
    // decompile the one(s) calling the most converters = the dispatcher
    long best=0; int bestN=0; for(Map.Entry<Long,Integer> e:callerCount.entrySet()) if(e.getValue()>bestN){bestN=e.getValue();best=e.getKey();}
    if(best!=0){
      pw.println("\n############ DISPATCHER FUN_"+Long.toHexString(best)+" (calls "+bestN+" converters) ############");
      Function f=fm.getFunctionContaining(sp.getAddress(best));
      DecompileResults r=di.decompileFunction(f,120,monitor);
      pw.println(r!=null&&r.decompileCompleted()?r.getDecompiledFunction().getC():"<fail>");
      pw.println("---- entry bytes ----");
      Listing lst=currentProgram.getListing(); InstructionIterator ii=lst.getInstructions(f.getBody(),true); int n=0;
      while(ii.hasNext()&&n<10){ Instruction ins=ii.next(); StringBuilder b=new StringBuilder();
        try{for(byte x:ins.getBytes())b.append(String.format("%02x ",x&0xff));}catch(Exception e){}
        pw.println(String.format("  0x%08x  %-20s %s",ins.getAddress().getOffset(),b.toString().trim(),ins.toString())); n++; }
    }
    pw.close(); println("wrote re/dispatch.txt best=FUN_"+Long.toHexString(best));
  }
}
