import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.app.decompiler.*;
import java.io.*;
import java.util.*;

// Dump the GWCanvas vtable (0x6720fc) and decompile each method, flagging ones
// that touch offsets near the cursor-on flag (0x1ac) - the cursor x/y updater.
public class VtScan extends GhidraScript {
  public void run() throws Exception {
    AddressSpace sp = currentProgram.getAddressFactory().getDefaultAddressSpace();
    Memory mem = currentProgram.getMemory();
    DecompInterface di = new DecompInterface(); di.openProgram(currentProgram);
    PrintWriter pw = new PrintWriter(new FileWriter("C:\\Users\\Joe\\Desktop\\Tribes Browser Based\\re\\vtscan.txt"));

    long vt = 0x6720fcL;
    Set<Long> seen = new HashSet<>();
    for (int i = 0; i < 80; i++) {
      long fn = mem.getInt(sp.getAddress(vt + i * 4)) & 0xFFFFFFFFL;
      if (fn < 0x401000 || fn > 0x6e0000) continue;
      if (!seen.add(fn)) continue;
      Function f = currentProgram.getFunctionManager().getFunctionContaining(sp.getAddress(fn));
      if (f == null) continue;
      DecompileResults r = di.decompileFunction(f, 60, monitor);
      if (r == null || r.getDecompiledFunction() == null) continue;
      String c = r.getDecompiledFunction().getC();
      // flag methods touching the cursor region (0x1a0..0x1bc)
      if (c.contains("0x1ac") || c.contains("0x1a4") || c.contains("0x1a8") ||
          c.contains("0x1b0") || c.contains("0x1a0") || c.contains("0x1b4") || c.contains("0x1b8")) {
        pw.println("\n\n######## vtable[" + i + "] = 0x" + Long.toHexString(fn) + " (touches cursor region) ########");
        pw.println(c);
      }
    }
    pw.close(); println("wrote vtscan.txt");
  }
}
