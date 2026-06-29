// DecompTex — decompile 1.40's bitmap load path to learn the IN-MEMORY texture format: GFXBitmap::Read
// (FUN_004180c0) + the PNG loader (FUN_00418770). The key question: does it keep the decoded bitmap at
// the PNG's depth (24/32-bit truecolor -> cache bloat) or down-convert to 8-bit palettized (no bloat)?
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.app.decompiler.*;
import java.io.*;

public class DecompTex extends GhidraScript {
  public void run() throws Exception {
    AddressSpace sp=currentProgram.getAddressFactory().getDefaultAddressSpace();
    DecompInterface di=new DecompInterface(); di.openProgram(currentProgram);
    PrintWriter pw=new PrintWriter(new BufferedWriter(new FileWriter(
      System.getProperty("user.home")+"/dectex.txt")));
    pw.println("program="+currentProgram.getName());
    long[] fns={0x4180c0L,0x418770L};
    for(long va:fns){
      Function f=currentProgram.getFunctionManager().getFunctionContaining(sp.getAddress(va));
      pw.println("\n========== 0x"+Long.toHexString(va)+(f!=null?" "+f.getName():" (NO FUNCTION)")+" ==========");
      if(f!=null){
        DecompileResults r=di.decompileFunction(f,90,monitor);
        if(r!=null&&r.decompileCompleted()){ String c=r.getDecompiledFunction().getC();
          pw.println(c.length()>5000?c.substring(0,5000):c); }
        // small callees (the per-format decoders / bitmap allocators)
        for(Function cal: f.getCalledFunctions(monitor)){
          if(cal.getBody().getNumAddresses()>400) continue;
          DecompileResults r2=di.decompileFunction(cal,40,monitor);
          if(r2!=null&&r2.decompileCompleted()){ String c2=r2.getDecompiledFunction().getC();
            pw.println("  --- callee "+cal.getName()+" @0x"+Long.toHexString(cal.getEntryPoint().getOffset())+" ---");
            pw.println("  "+(c2.length()>1200?c2.substring(0,1200):c2)); }
        }
      }
    }
    pw.close(); println("wrote re/dectex.txt program="+currentProgram.getName());
  }
}
