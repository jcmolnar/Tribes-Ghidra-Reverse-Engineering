import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.app.decompiler.*;
import java.io.*;

// Confirm the 1.40 CMDConsole entry points (evaluate / executef) and locate the
// playGui/HUD render seam for the Hudbot ScriptGL onPreDraw/onPostDraw hook.
public class HudbotSeam extends GhidraScript {
  DecompInterface di;
  PrintWriter pw;

  void dump(long addr, String note) throws Exception {
    AddressSpace sp = currentProgram.getAddressFactory().getDefaultAddressSpace();
    Function f = currentProgram.getFunctionManager().getFunctionContaining(sp.getAddress(addr));
    pw.println("\n========== 0x" + Long.toHexString(addr) + "  " + note + " ==========");
    if (f == null) { pw.println("  (no function)"); return; }
    pw.println("  entry=" + f.getEntryPoint());
    DecompileResults r = di.decompileFunction(f, 60, monitor);
    if (r != null && r.getDecompiledFunction() != null)
      pw.println(r.getDecompiledFunction().getC());
  }

  public void run() throws Exception {
    di = new DecompInterface();
    di.openProgram(currentProgram);
    pw = new PrintWriter(new FileWriter(System.getProperty("user.home")+"/hudbot_seam.txt"));

    dump(0x403600L, "addCommand(Callback) [TribesXT]");
    dump(0x403640L, "evaluate?? / addCommand(CMDCallback*) [TribesXT dup]");
    dump(0x403680L, "executef [TribesXT]");

    // Find strings that name the render/playGui seam, list their references.
    SymbolTable st = currentProgram.getSymbolTable();
    String[] needles = {"renderCanvas", "playGui", "PlayGui", "onPreDraw", "Canvas", "ScriptGL"};
    pw.println("\n\n===== string references =====");
    DataIterator di2 = currentProgram.getListing().getDefinedData(true);
    while (di2.hasNext()) {
      Data d = di2.next();
      Object v = d.getValue();
      if (!(v instanceof String)) continue;
      String s = (String) v;
      for (String n : needles) {
        if (s.contains(n)) {
          pw.println("\n\"" + s + "\" @ " + d.getAddress());
          ReferenceIterator ri = currentProgram.getReferenceManager().getReferencesTo(d.getAddress());
          int c = 0;
          while (ri.hasNext() && c < 8) {
            Reference rf = ri.next();
            Function f = currentProgram.getFunctionManager().getFunctionContaining(rf.getFromAddress());
            pw.println("   <- " + rf.getFromAddress() + (f != null ? ("  in " + f.getName() + " @" + f.getEntryPoint()) : ""));
            c++;
          }
          break;
        }
      }
    }
    pw.close();
    println("wrote hudbot_seam.txt");
  }
}
