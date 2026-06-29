// MemDecomp — decompile specific membot functions by RVA (base 0x10000000).
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.app.decompiler.*;
import java.io.*;

public class MemDecomp extends GhidraScript {
  public void run() throws Exception {
    AddressSpace sp=currentProgram.getAddressFactory().getDefaultAddressSpace();
    FunctionManager fm=currentProgram.getFunctionManager();
    DecompInterface di=new DecompInterface(); di.openProgram(currentProgram);
    long[] rvas = {0x1fc0,0x1f60,0x1d60,0x2da0,0x2100,0x2700,0x2900,0x2c00,0x2e30,0x5c50};
    PrintWriter pw=new PrintWriter(new BufferedWriter(new FileWriter(
      "C:\\Users\\Joe\\Desktop\\Tribes Browser Based\\re\\mem_funcs.txt")));
    for(long rva:rvas){
      Address a=sp.getAddress(0x10000000L+rva);
      Function f=fm.getFunctionContaining(a);
      if(f==null){ pw.println("=== rva 0x"+Long.toHexString(rva)+" : NO FUNCTION ==="); continue; }
      pw.println("======================================================");
      pw.println("=== rva 0x"+Long.toHexString(rva)+"  FUNC "+f.getName()+" @0x"+Long.toHexString(f.getEntryPoint().getOffset())+" ===");
      DecompileResults r=di.decompileFunction(f,90,monitor);
      pw.println((r!=null&&r.decompileCompleted())? r.getDecompiledFunction().getC():"<fail>");
      pw.println();
    }
    pw.close();
    println("wrote re/mem_funcs.txt");
  }
}
