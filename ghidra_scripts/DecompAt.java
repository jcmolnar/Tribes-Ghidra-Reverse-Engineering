// DecompAt — decompile the function containing a fixed address (the crash EIP) and print it,
// flagging the crash line. Address is hardcoded. Output: re/crash_fn.txt
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.app.decompiler.*;
import java.io.*;

public class DecompAt extends GhidraScript {
  public void run() throws Exception {
    long crash = 0x46d867L;
    AddressSpace sp=currentProgram.getAddressFactory().getDefaultAddressSpace();
    FunctionManager fm=currentProgram.getFunctionManager();
    DecompInterface di=new DecompInterface(); di.openProgram(currentProgram);
    Function f=fm.getFunctionContaining(sp.getAddress(crash));
    PrintWriter pw=new PrintWriter(new BufferedWriter(new FileWriter(
      "C:\\Users\\Joe\\Desktop\\Tribes Browser Based\\re\\crash_fn.txt")));
    if(f==null){ pw.println("no function at 0x"+Long.toHexString(crash)); pw.close(); println("no func"); return; }
    pw.println("crash EIP 0x"+Long.toHexString(crash)+" in "+f.getName()+" @0x"+Long.toHexString(f.getEntryPoint().getOffset()));
    // disassembly around the crash
    pw.println("\n---- instructions around crash ----");
    Listing lst=currentProgram.getListing();
    Address a=sp.getAddress(crash-0x20);
    for(int i=0;i<20;i++){
      Instruction ins=lst.getInstructionAt(a);
      if(ins==null){ a=a.add(1); continue; }
      String mark = (ins.getAddress().getOffset()==crash)?"  <<<<< CRASH":"";
      pw.println(String.format("  0x%08x  %s%s", ins.getAddress().getOffset(), ins.toString(), mark));
      a=ins.getAddress().add(ins.getLength());
      if(a.getOffset()>crash+0x10) break;
    }
    pw.println("\n---- decompile ----");
    DecompileResults r=di.decompileFunction(f,60,monitor);
    pw.println((r!=null&&r.decompileCompleted())? r.getDecompiledFunction().getC():"  <fail>");
    pw.close();
    println("wrote re/crash_fn.txt  func="+f.getName());
  }
}
