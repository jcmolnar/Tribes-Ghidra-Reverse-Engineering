import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.app.decompiler.*;
import java.io.*;

public class CallerOf extends GhidraScript {
  public void run() throws Exception {
    AddressSpace sp = currentProgram.getAddressFactory().getDefaultAddressSpace();
    DecompInterface di = new DecompInterface();
    di.openProgram(currentProgram);
    PrintWriter pw = new PrintWriter(new BufferedWriter(new FileWriter(
      "C:\\Users\\Joe\\Desktop\\Tribes Browser Based\\re\\callerof.txt")));
    ReferenceIterator it = currentProgram.getReferenceManager().getReferencesTo(sp.getAddress(0x423158L));
    while (it.hasNext()) {
      Reference r = it.next();
      if (!r.getReferenceType().isCall()) continue;
      Function f = currentProgram.getFunctionManager().getFunctionContaining(r.getFromAddress());
      pw.println("=== caller 0x" + Long.toHexString(r.getFromAddress().getOffset())
        + (f != null ? " in " + f.getName() + " @0x" + Long.toHexString(f.getEntryPoint().getOffset()) : "") + " ===");
      if (f != null) {
        DecompileResults dr = di.decompileFunction(f, 60, monitor);
        if (dr != null && dr.decompileCompleted()) {
          String c = dr.getDecompiledFunction().getC();
          pw.println(c.length() > 4500 ? c.substring(0, 4500) : c);
        }
      }
    }
    pw.close();
    println("wrote re/callerof.txt");
  }
}
