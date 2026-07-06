// PersistSlot — DEFINITIVE: which vtable slot does the .gui persist loader call for read/write?
// Decompile the child-object reader FUN_004ff54c (called by SimGroup::read) + FUN_004ff044
// (SimGroup own-field read) + the object load/save entry, and disassemble the indirect call so
// we see the exact vtable offset. Also decompile FGSlider's OWN-module vtable fns (0x4c8948,
// 0x4c9158, 0x4c9160, 0x542b78, 0x48c7f0, 0x4b36e4) to find its true binary persist read override.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.app.decompiler.*;
import java.io.*;

public class PersistSlot extends GhidraScript {
  Memory mem; FunctionManager fm; AddressSpace sp; DecompInterface di; PrintWriter pw; Listing lst;
  String dc(long va){
    try{ Address pa=sp.getAddress(va); Function f=fm.getFunctionAt(pa);
      if(f==null){ disassemble(pa); f=createFunction(pa,null); if(f==null)f=fm.getFunctionContaining(pa);}
      if(f==null)return "  <no fn>";
      DecompileResults r=di.decompileFunction(f,90,monitor);
      return (r!=null&&r.decompileCompleted())?r.getDecompiledFunction().getC():"  <fail>";
    }catch(Exception e){return "  <exc "+e+">";}
  }
  void disasm(long start,long end){
    Address a=sp.getAddress(start);
    while(a.getOffset()<end){
      Instruction ins=lst.getInstructionAt(a);
      if(ins==null){ try{ disassemble(a);}catch(Exception e){} ins=lst.getInstructionAt(a); }
      if(ins==null){ pw.println(String.format("  %08x  <no insn>",a.getOffset())); a=a.add(1); continue; }
      pw.println(String.format("  %08x  %s", a.getOffset(), ins.toString()));
      a=a.add(ins.getLength());
    }
  }
  public void run() throws Exception {
    mem=currentProgram.getMemory(); fm=currentProgram.getFunctionManager();
    sp=currentProgram.getAddressFactory().getDefaultAddressSpace(); lst=currentProgram.getListing();
    di=new DecompInterface(); di.openProgram(currentProgram);
    pw=new PrintWriter(new BufferedWriter(new FileWriter(
      "C:\\Users\\Joe\\Desktop\\Tribes Browser Based\\re\\persist_slot.txt")));

    long[] fns = {0x4ff54cL, 0x4ff044L, 0x4fefdcL, 0x4feeecL, 0x4ff508L,
                  0x4c8948L,0x4c9158L,0x4c9160L,0x542b78L,0x48c7f0L,0x4b36e4L,0x4c95ccL};
    String[] nm = {"FUN_004ff54c persist readObject(stream)","FUN_004ff044 SimGroup own-read",
      "FUN_004fefdc SimGroup own-write","FUN_004feeec SimSet base read?","FUN_004ff508 persist writeObject",
      "FGSlider 0x4c8948","FGSlider 0x4c9158","FGSlider 0x4c9160","FGSlider-base 0x542b78",
      "FGSlider-base 0x48c7f0","FGSlider-base 0x4b36e4","FGSlider ctor 0x4c95cc"};
    for(int i=0;i<fns.length;i++){
      pw.println("\n================ "+nm[i]+" @0x"+Long.toHexString(fns[i])+" ================");
      pw.println(dc(fns[i]));
    }
    pw.println("\n\n######## RAW DISASM FUN_004ff54c (find read vtable offset) ########");
    disasm(0x4ff54cL,0x4ff5f0L);
    pw.close(); println("wrote re/persist_slot.txt");
  }
}
