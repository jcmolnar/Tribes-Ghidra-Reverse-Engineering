// BitmapRE — locate GFXBitmap::Read and its format dispatch in Tribes 1.40.655.
// Find the "... bitmaps are not supported" strings, decompile the functions that reference them
// (the format check) AND their callers (the Read dispatcher), so we learn: dispatch-by-extension vs
// dispatch-by-magic, which formats are accepted (PNG path), and where to hook to add Microsoft BMP.
// Output: re/bitmap_re.txt
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.app.decompiler.*;
import java.io.*;
import java.util.*;

public class BitmapRE extends GhidraScript {
  DecompInterface di; FunctionManager fm; PrintWriter pw;
  Set<Long> done = new HashSet<Long>();

  void decompFn(Function f, String why) {
    if (f == null) return;
    long key = f.getEntryPoint().getOffset();
    if (!done.add(key)) return;
    pw.println("\n================ " + f.getName(true) + " @0x" + Long.toHexString(key) + "  [" + why + "] ================");
    DecompileResults r = di.decompileFunction(f, 60, monitor);
    pw.println((r != null && r.decompileCompleted()) ? r.getDecompiledFunction().getC() : "  <decompile failed>");
  }

  void refsToString(String s) throws Exception {
    pw.println("\n##################### refs to: \"" + s + "\" #####################");
    Address a = find(s);
    if (a == null) { pw.println("  <string not found>"); return; }
    pw.println("  string @0x" + Long.toHexString(a.getOffset()));
    ReferenceManager rm = currentProgram.getReferenceManager();
    ReferenceIterator it = rm.getReferencesTo(a);
    List<Function> callers = new ArrayList<Function>();
    while (it.hasNext()) {
      Reference r = it.next();
      Function f = fm.getFunctionContaining(r.getFromAddress());
      pw.println("  xref from 0x" + Long.toHexString(r.getFromAddress().getOffset())
                 + " in " + (f != null ? f.getName(true) : "<none>"));
      if (f != null) callers.add(f);
    }
    for (Function f : callers) {
      decompFn(f, "references string");
      // also decompile its callers (the dispatcher one level up)
      Set<Function> up = f.getCallingFunctions(monitor);
      for (Function c : up) decompFn(c, "caller of " + f.getName());
    }
  }

  public void run() throws Exception {
    di = new DecompInterface(); di.openProgram(currentProgram);
    fm = currentProgram.getFunctionManager();
    pw = new PrintWriter(new BufferedWriter(new FileWriter(
        System.getProperty("user.home")+"/bitmap_re.txt")));
    pw.println("GFXBitmap format-loader RE — Tribes 1.40.655");
    refsToString("Microsoft bitmaps are not supported");
    refsToString("Phoenix bitmaps are not supported");
    refsToString("GFXBitmap::Read");
    pw.close();
    println("wrote re/bitmap_re.txt");
  }
}
