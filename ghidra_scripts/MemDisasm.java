// MemDisasm — force-disassemble + decompile membot routines that Ghidra missed,
// by creating functions at given RVAs first. base 0x10000000.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.app.decompiler.*;
import ghidra.app.cmd.disassemble.*;
import ghidra.app.cmd.function.*;
import java.io.*;

public class MemDisasm extends GhidraScript {
  public void run() throws Exception {
    AddressSpace sp=currentProgram.getAddressFactory().getDefaultAddressSpace();
    FunctionManager fm=currentProgram.getFunctionManager();
    long[] rvas = {0x1fc0,0x1f60,0x2da0,0x1c50,0x1cf0};
    // First disassemble + make functions
    for(long rva:rvas){
      Address a=sp.getAddress(0x10000000L+rva);
      DisassembleCommand dc=new DisassembleCommand(a,null,true);
      dc.applyTo(currentProgram, monitor);
      if(fm.getFunctionAt(a)==null){
        CreateFunctionCmd cf=new CreateFunctionCmd(a);
        cf.applyTo(currentProgram, monitor);
      }
    }
    DecompInterface di=new DecompInterface(); di.openProgram(currentProgram);
    PrintWriter pw=new PrintWriter(new BufferedWriter(new FileWriter(
      System.getProperty("user.home")+"/mem_patcher.txt")));
    Listing lst=currentProgram.getListing();
    for(long rva:rvas){
      Address a=sp.getAddress(0x10000000L+rva);
      pw.println("======================================================");
      pw.println("=== rva 0x"+Long.toHexString(rva)+" ===");
      // raw disasm first 60 instrs
      Address cur=a;
      for(int i=0;i<70;i++){
        Instruction ins=lst.getInstructionAt(cur);
        if(ins==null) break;
        pw.println(String.format("  0x%08x  %s", cur.getOffset(), ins.toString()));
        cur=cur.add(ins.getLength());
      }
      Function f=fm.getFunctionContaining(a);
      if(f!=null){
        pw.println("--- decompile "+f.getName()+" ---");
        DecompileResults r=di.decompileFunction(f,90,monitor);
        pw.println((r!=null&&r.decompileCompleted())? r.getDecompiledFunction().getC():"<fail>");
      }
      pw.println();
    }
    pw.close();
    println("wrote re/mem_patcher.txt");
  }
}
