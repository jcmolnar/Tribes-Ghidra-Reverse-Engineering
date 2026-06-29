// CallersUp — find + decompile callers of the glTexImage2D wrapper FUN_005dc320 (the real texture
// converters that hold the source bitmap). Output: re/callersup.txt
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.app.decompiler.*;
import java.io.*;
import java.util.*;
public class CallersUp extends GhidraScript {
  public void run() throws Exception {
    AddressSpace sp=currentProgram.getAddressFactory().getDefaultAddressSpace();
    FunctionManager fm=currentProgram.getFunctionManager();
    DecompInterface di=new DecompInterface(); di.openProgram(currentProgram);
    PrintWriter pw=new PrintWriter(new BufferedWriter(new FileWriter(System.getProperty("user.home")+"/callersup.txt")));
    Set<Long> seen=new LinkedHashSet<Long>();
    ReferenceIterator it=currentProgram.getReferenceManager().getReferencesTo(sp.getAddress(0x5dc320L));
    while(it.hasNext()){
      Reference r=it.next(); if(!r.getReferenceType().isCall()) continue;
      Function f=fm.getFunctionContaining(r.getFromAddress()); if(f==null) continue;
      long fa=f.getEntryPoint().getOffset();
      pw.println("caller 0x"+Long.toHexString(r.getFromAddress().getOffset())+" in FUN_"+Long.toHexString(fa));
      if(seen.add(fa)){
        DecompileResults dr=di.decompileFunction(f,120,monitor);
        pw.println(dr!=null&&dr.decompileCompleted()?dr.getDecompiledFunction().getC():"<fail>");
        pw.println("---- entry bytes ----");
        Listing lst=currentProgram.getListing(); InstructionIterator ii=lst.getInstructions(f.getBody(),true); int n=0;
        while(ii.hasNext()&&n<4){ Instruction ins=ii.next(); StringBuilder b=new StringBuilder();
          try{for(byte x:ins.getBytes())b.append(String.format("%02x ",x&0xff));}catch(Exception e){}
          pw.println(String.format("  0x%08x  %s  %s",ins.getAddress().getOffset(),b.toString().trim(),ins.toString())); n++; }
      }
    }
    pw.close(); println("wrote re/callersup.txt callers="+seen);
  }
}
