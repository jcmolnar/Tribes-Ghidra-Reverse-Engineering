// UpFn — decompile the single glTexImage2D uploader (function containing 0x5dc347) + disasm,
// so we can find its source-bitmap argument and entry to hook. Output: re/upfn.txt
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.app.decompiler.*;
import java.io.*;
public class UpFn extends GhidraScript {
  public void run() throws Exception {
    long site=0x5dc347L;
    AddressSpace sp=currentProgram.getAddressFactory().getDefaultAddressSpace();
    FunctionManager fm=currentProgram.getFunctionManager();
    DecompInterface di=new DecompInterface(); di.openProgram(currentProgram);
    Function f=fm.getFunctionContaining(sp.getAddress(site));
    PrintWriter pw=new PrintWriter(new BufferedWriter(new FileWriter(System.getProperty("user.home")+"/upfn.txt")));
    if(f==null){ pw.println("no fn"); pw.close(); return; }
    pw.println("uploader FUN_"+Long.toHexString(f.getEntryPoint().getOffset())+"  (glTexImage2D call @0x"+Long.toHexString(site)+")");
    DecompileResults r=di.decompileFunction(f,120,monitor);
    pw.println(r!=null&&r.decompileCompleted()?r.getDecompiledFunction().getC():"<fail>");
    pw.println("\n---- prologue disasm ----");
    Listing lst=currentProgram.getListing();
    InstructionIterator it=lst.getInstructions(f.getBody(),true);
    int n=0;
    while(it.hasNext() && n<16){ Instruction ins=it.next(); StringBuilder b=new StringBuilder();
      try{for(byte x:ins.getBytes())b.append(String.format("%02x ",x&0xff));}catch(Exception e){}
      pw.println(String.format("  0x%08x  %-22s %s",ins.getAddress().getOffset(),b.toString().trim(),ins.toString())); n++; }
    pw.close(); println("wrote re/upfn.txt fn="+Long.toHexString(f.getEntryPoint().getOffset()));
  }
}
