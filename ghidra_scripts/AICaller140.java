// AICaller140 — identify what FUN_004298c0 IS in 1.40: dump its caller FUN_0042f980, find string refs
// nearby (to name the AI/scope path), and check if 0x4298c0 sits in any data/vtable (RTTI) by scanning
// .rdata for pointers to it. Helps name the function (scope-name query) for the deliverable.
// Output: re/aicaller140.txt
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.mem.*;
import ghidra.app.decompiler.*;
import java.io.*;
import java.util.*;

public class AICaller140 extends GhidraScript {
  DecompInterface di; FunctionManager fm; AddressSpace sp; Listing lst; Memory mem; SymbolTable st; PrintWriter pw;
  String dec(Function f){
    DecompileResults r=di.decompileFunction(f,120,monitor);
    return (r!=null&&r.decompileCompleted())? r.getDecompiledFunction().getC():"  <fail>";
  }
  public void run() throws Exception {
    di=new DecompInterface(); di.openProgram(currentProgram);
    fm=currentProgram.getFunctionManager(); sp=currentProgram.getAddressFactory().getDefaultAddressSpace();
    lst=currentProgram.getListing(); mem=currentProgram.getMemory(); st=currentProgram.getSymbolTable();
    pw=new PrintWriter(new BufferedWriter(new FileWriter("C:\\Users\\Joe\\Desktop\\Tribes Browser Based\\re\\aicaller140.txt")));

    long fnVA=0x4298c0L;

    // scan all initialized memory for a 4-byte pointer == 0x4298c0 (in vtables / function tables / data)
    pw.println("---- data/code pointers to 0x4298c0 (vtable / tables) ----");
    for(MemoryBlock b: mem.getBlocks()){
      if(!b.isInitialized()) continue;
      long start=b.getStart().getOffset(), e=b.getEnd().getOffset();
      for(long p=start; p+4<=e; p+=4){
        long v;
        try{ v=mem.getInt(sp.getAddress(p)) & 0xffffffffL; }catch(Exception ex){ continue; }
        if(v==fnVA){
          Symbol s=st.getPrimarySymbol(sp.getAddress(p));
          pw.println("   ptr@0x"+Long.toHexString(p)+"  block="+b.getName()+"  sym="+(s!=null?s.getName(true):""));
        }
      }
    }

    // caller
    pw.println("\n############ caller FUN_0042f980 @0x42f980 ############");
    Function cf=fm.getFunctionAt(sp.getAddress(0x42f980L));
    if(cf!=null) pw.println(dec(cf)); else pw.println("  <none>");

    // string references inside the caller & the target fn
    pw.println("\n---- string refs in FUN_0042f980 + FUN_004298c0 ----");
    long[] fns={0x42f980L, 0x4298c0L};
    for(long fv: fns){
      Function f=fm.getFunctionAt(sp.getAddress(fv));
      if(f==null) continue;
      Address a=f.getEntryPoint(), end=f.getBody().getMaxAddress();
      while(a!=null && a.compareTo(end)<=0){
        Instruction ins=lst.getInstructionAt(a); if(ins==null){a=a.add(1);continue;}
        Reference[] refs=ins.getReferencesFrom();
        for(Reference rf: refs){
          Data d=lst.getDataAt(rf.getToAddress());
          if(d!=null && d.hasStringValue()){
            pw.println("   0x"+Long.toHexString(fv)+": \""+d.getValue()+"\"");
          }
        }
        a=ins.getAddress().add(ins.getLength());
      }
    }
    pw.close();
    println("wrote re/aicaller140.txt");
  }
}
