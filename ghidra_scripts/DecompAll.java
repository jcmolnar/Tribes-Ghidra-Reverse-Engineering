// DecompAll — decompile EVERY function in the current program + dump rdata strings. For the tiny
// mem.dll loader: reveals the getPlugin GetProcAddress + how it walks the descriptor to register cmds.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import ghidra.app.decompiler.*;
import java.io.*;

public class DecompAll extends GhidraScript {
  public void run() throws Exception {
    DecompInterface di = new DecompInterface(); di.openProgram(currentProgram);
    PrintWriter pw = new PrintWriter(new BufferedWriter(new FileWriter(
      "C:\\Users\\Joe\\Desktop\\Tribes Browser Based\\re\\memdll.txt")));
    FunctionManager fm = currentProgram.getFunctionManager();
    pw.println("imageBase=0x" + Long.toHexString(currentProgram.getImageBase().getOffset()));
    int n = 0;
    for (Function f : fm.getFunctions(true)) {
      n++;
      pw.println("\n===== " + f.getName() + " @0x" + Long.toHexString(f.getEntryPoint().getOffset())
                 + " (size " + f.getBody().getNumAddresses() + ") =====");
      DecompileResults r = di.decompileFunction(f, 60, monitor);
      if (r != null && r.decompileCompleted()) pw.println(r.getDecompiledFunction().getC());
      else pw.println("  <decompile failed>");
    }
    // dump defined strings (rdata)
    pw.println("\n===== strings =====");
    DataIterator dit = currentProgram.getListing().getDefinedData(true);
    while (dit.hasNext()) {
      Data d = dit.next(); Object v = d.getValue();
      if (v instanceof String) pw.println("  0x" + Long.toHexString(d.getAddress().getOffset()) + ": \"" + v + "\"");
    }
    pw.close(); println("wrote re/memdll.txt (" + n + " fns)");
  }
}
