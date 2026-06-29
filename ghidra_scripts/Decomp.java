import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.app.decompiler.*;
import java.io.*;

// Decompile a fixed list of addresses (edit `addrs`) to re/decomp_out.txt.
public class Decomp extends GhidraScript {
  public void run() throws Exception {
    long[] addrs = { 0x540670L, 0x540d30L, 0x5476d0L };
    AddressSpace sp = currentProgram.getAddressFactory().getDefaultAddressSpace();
    DecompInterface di = new DecompInterface(); di.openProgram(currentProgram);
    PrintWriter pw = new PrintWriter(new FileWriter(System.getProperty("user.home")+"/decomp_out.txt"));
    for (long a : addrs) {
      Function f = currentProgram.getFunctionManager().getFunctionContaining(sp.getAddress(a));
      pw.println("\n\n======== 0x" + Long.toHexString(a) + (f!=null?("  fn="+f.getEntryPoint()):" (none)") + " ========");
      if (f == null) continue;
      DecompileResults r = di.decompileFunction(f, 120, monitor);
      if (r != null && r.getDecompiledFunction() != null) pw.println(r.getDecompiledFunction().getC());
    }
    pw.close(); println("wrote decomp_out.txt");
  }
}
