// PersistDispatch — THE linchpin. Disassemble Persistent::readObject FUN_0058b2e0 and
// writeObject FUN_0058b540 to read the EXACT vtable offset the .gui loader dispatches read/write
// through. That single offset tells us whether persist read is slot 0 or slot 10 — resolving the
// FGSlider format for good. Also decompile FUN_0058b2e0/540 and Persistent::create region.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.app.decompiler.*;
import java.io.*;

public class PersistDispatch extends GhidraScript {
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
      "C:\\Users\\Joe\\Desktop\\Tribes Browser Based\\re\\persist_dispatch.txt")));
    pw.println("======== FUN_0058b2e0 Persistent::readObject (decompile) ========");
    pw.println(dc(0x58b2e0L));
    pw.println("\n======== FUN_0058b2e0 (raw disasm) ========");
    disasm(0x58b2e0L,0x58b420L);
    pw.println("\n\n======== FUN_0058b540 Persistent::writeObject (decompile) ========");
    pw.println(dc(0x58b540L));
    pw.println("\n======== FUN_0058b540 (raw disasm) ========");
    disasm(0x58b540L,0x58b640L);
    pw.close(); println("wrote re/persist_dispatch.txt");
  }
}
