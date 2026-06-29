// MemPatch — locate membot.dll's patch mechanism in the UNPACKED image.
// Strategy:
//  1) Find the string "VirtualProtect" and "membot.dll (0.5.18) loaded".
//  2) Find code that references them (the dynamic-API-resolver + the init/patch routine).
//  3) Decompile those functions + their callers, write to re/mem_dllmain.txt.
//  4) Scan .text for memory writes whose destination is in the T1Vista range
//     (0x400000..0x582000) to surface patch sites.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.scalar.*;
import ghidra.app.decompiler.*;
import java.io.*;
import java.util.*;

public class MemPatch extends GhidraScript {
  public void run() throws Exception {
    Memory mem=currentProgram.getMemory();
    AddressSpace sp=currentProgram.getAddressFactory().getDefaultAddressSpace();
    Listing lst=currentProgram.getListing();
    FunctionManager fm=currentProgram.getFunctionManager();
    DecompInterface di=new DecompInterface(); di.openProgram(currentProgram);
    PrintWriter pw=new PrintWriter(new BufferedWriter(new FileWriter(
      System.getProperty("user.home")+"/mem_dllmain.txt")));

    // locate key strings
    long base=0x10000000L;
    String[] keys={"VirtualProtect","membot.dll","GetProcAddress","WriteProcessMemory","Endframe","MouseEnable","pref::display::gammaValue"};
    HashMap<String,Long> strAddr=new HashMap<>();
    for(String k:keys){
      Address fa=find(null, k.getBytes());
      if(fa!=null){ strAddr.put(k, fa.getOffset()); pw.println("STR \""+k+"\" @ 0x"+Long.toHexString(fa.getOffset())); }
      else pw.println("STR \""+k+"\" NOT FOUND");
    }
    pw.println();

    // For each located string, find references and the containing functions.
    HashSet<Function> interesting=new HashSet<>();
    for(Map.Entry<String,Long> en:strAddr.entrySet()){
      Address sa=sp.getAddress(en.getValue());
      ReferenceIterator ri=currentProgram.getReferenceManager().getReferencesTo(sa);
      pw.println("REFS to \""+en.getKey()+"\":");
      int n=0;
      while(ri.hasNext() && n<20){
        Reference r=ri.next(); Address from=r.getFromAddress();
        Function f=fm.getFunctionContaining(from);
        pw.println("   from 0x"+Long.toHexString(from.getOffset())+(f!=null?(" in "+f.getName()+" @0x"+Long.toHexString(f.getEntryPoint().getOffset())):" (no func)"));
        if(f!=null) interesting.add(f);
        n++;
      }
      pw.println();
    }

    // Decompile interesting functions
    for(Function f:interesting){
      pw.println("==================================================================");
      pw.println("FUNC "+f.getName()+" @ 0x"+Long.toHexString(f.getEntryPoint().getOffset()));
      DecompileResults r=di.decompileFunction(f,90,monitor);
      pw.println((r!=null&&r.decompileCompleted())? r.getDecompiledFunction().getC() : "  <decompile fail>");
      pw.println();
    }
    pw.close();
    println("wrote re/mem_dllmain.txt; interesting funcs="+interesting.size());

    // Scan .text for instructions that write a dword/byte to an absolute T1Vista-range address.
    PrintWriter pw2=new PrintWriter(new BufferedWriter(new FileWriter(
      System.getProperty("user.home")+"/mem_writesites.txt")));
    MemoryBlock textb=mem.getBlock(".text");
    InstructionIterator ii=lst.getInstructions(textb.getStart(), true);
    int writes=0;
    while(ii.hasNext()){
      Instruction ins=ii.next();
      String m=ins.getMnemonicString();
      // look for mov [imm32], ... where imm32 in T1Vista range; or references to data in that range
      for(int op=0; op<ins.getNumOperands(); op++){
        Object[] objs=ins.getOpObjects(op);
        for(Object o:objs){
          if(o instanceof Scalar){
            long v=((Scalar)o).getUnsignedValue();
            if(v>=0x401000L && v<=0x582000L && (m.equals("MOV")||m.equals("CALL")||m.equals("PUSH")||m.equals("LEA")||m.equals("ADD")||m.equals("CMP"))){
              Function f=fm.getFunctionContaining(ins.getAddress());
              pw2.println("0x"+Long.toHexString(ins.getAddress().getOffset())+"  "+ins.toString()+"  [T1Vista VA 0x"+Long.toHexString(v)+"]"+(f!=null?("  fn@0x"+Long.toHexString(f.getEntryPoint().getOffset())):""));
              writes++;
            }
          }
        }
      }
    }
    pw2.close();
    println("wrote re/mem_writesites.txt; sites="+writes);
  }
}
