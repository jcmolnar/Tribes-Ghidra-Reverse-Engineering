import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.app.decompiler.*;
import java.io.*;

// Locate the engine's GUI cursor: the cursorOn/isCursorOn/setCursor console
// handlers (-> the canvas object + cursor on-flag) and where the cursor x/y is
// stored/updated, so the Hudbot DLL can read the real (DirectInput-driven) cursor.
public class HudbotCursor extends GhidraScript {
  DecompInterface di;
  PrintWriter pw;

  void decompAt(Address a, String note) throws Exception {
    Function f = currentProgram.getFunctionManager().getFunctionContaining(a);
    pw.println("\n===== " + note + " @ " + a + (f != null ? ("  fn=" + f.getEntryPoint()) : " (no fn)") + " =====");
    if (f == null) return;
    DecompileResults r = di.decompileFunction(f, 60, monitor);
    if (r != null && r.getDecompiledFunction() != null) pw.println(r.getDecompiledFunction().getC());
  }

  public void run() throws Exception {
    di = new DecompInterface(); di.openProgram(currentProgram);
    pw = new PrintWriter(new FileWriter(System.getProperty("user.home")+"/hudbot_cursor.txt"));

    String[] needles = {"isCursorOn", "cursorOn", "setCursor", "lockMouse", "unlockMouse"};
    DataIterator it = currentProgram.getListing().getDefinedData(true);
    while (it.hasNext()) {
      Data d = it.next();
      Object v = d.getValue();
      if (!(v instanceof String)) continue;
      String s = (String) v;
      for (String n : needles) {
        if (s.equals(n) || s.startsWith(n + " ") || s.startsWith(n + ":")) {
          pw.println("\n\n############ string \"" + s + "\" @ " + d.getAddress() + " ############");
          ReferenceIterator ri = currentProgram.getReferenceManager().getReferencesTo(d.getAddress());
          int c = 0;
          while (ri.hasNext() && c < 4) {
            Reference rf = ri.next();
            decompAt(rf.getFromAddress(), "xref from");
            c++;
          }
          break;
        }
      }
    }
    pw.close();
    println("wrote hudbot_cursor.txt");
  }
}
