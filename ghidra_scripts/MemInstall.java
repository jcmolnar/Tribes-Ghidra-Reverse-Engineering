// MemInstall — disassemble + decompile the membot install routines that set up
// patch records and call the patchers (0x1fc0 / 0x1f60). RVAs of install blocks.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.app.decompiler.*;
import ghidra.app.cmd.disassemble.*;
import ghidra.app.cmd.function.*;
import java.io.*;

public class MemInstall extends GhidraScript {
  public void run() throws Exception {
    AddressSpace sp=currentProgram.getAddressFactory().getDefaultAddressSpace();
    FunctionManager fm=currentProgram.getFunctionManager();
    // install-block RVAs (entry points to discover/disasm)
    long[] rvas = {0x5780,0x5700,0x8340,0x8b50,0x8b00,0x2400,0x23a0};
    for(long rva:rvas){
      Address a=sp.getAddress(0x10000000L+rva);
      new DisassembleCommand(a,null,true).applyTo(currentProgram, monitor);
    }
    Listing lst=currentProgram.getListing();
    DecompInterface di=new DecompInterface(); di.openProgram(currentProgram);
    PrintWriter pw=new PrintWriter(new BufferedWriter(new FileWriter(
      System.getProperty("user.home")+"/mem_install.txt")));
    // We want raw disasm of the call-site clusters. Disasm windows around each cluster.
    long[][] windows = {{0x2400,0x2440},{0x5790,0x5870},{0x8380,0x83c0},{0x8b90,0x8c00}};
    for(long[] w:windows){
      pw.println("======= disasm 0x"+Long.toHexString(w[0])+" .. 0x"+Long.toHexString(w[1])+" =======");
      Address cur=sp.getAddress(0x10000000L+w[0]);
      Address end=sp.getAddress(0x10000000L+w[1]);
      // ensure disassembled
      new DisassembleCommand(cur,null,true).applyTo(currentProgram, monitor);
      while(cur.compareTo(end)<0){
        Instruction ins=lst.getInstructionAt(cur);
        if(ins==null){ cur=cur.add(1); continue; }
        pw.println(String.format("  0x%08x  %s", cur.getOffset(), ins.toString()));
        cur=cur.add(ins.getLength());
      }
      pw.println();
    }
    // decompile the containing functions of the cluster starts
    long[] fstarts={0x57a7,0x838e,0x8b97,0x2407};
    for(long fr:fstarts){
      Address a=sp.getAddress(0x10000000L+fr);
      Function f=fm.getFunctionContaining(a);
      if(f==null){ new CreateFunctionCmd(a).applyTo(currentProgram,monitor); f=fm.getFunctionContaining(a); }
      pw.println("======= decompile containing 0x"+Long.toHexString(fr)+" =======");
      if(f!=null){
        pw.println("FUNC "+f.getName()+" @0x"+Long.toHexString(f.getEntryPoint().getOffset()));
        DecompileResults r=di.decompileFunction(f,120,monitor);
        pw.println((r!=null&&r.decompileCompleted())? r.getDecompiledFunction().getC():"<fail>");
      } else pw.println("no function");
      pw.println();
    }
    pw.close();
    println("wrote re/mem_install.txt");
  }
}
