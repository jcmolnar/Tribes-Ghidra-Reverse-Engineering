import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.app.decompiler.*;
import java.io.*;
import java.util.*;

// Map how textures load. List callers of the bitmap loaders (GFXBitmap::load 0x418570,
// read 0x4180c0) and the resource-by-name loader (0x415fd0), and decompile the bitmap-
// level callers (few, revealing: shows the shape/material/skin texture path vs the GUI
// ResourceManager path). Helps decide where to hook for DTS shape (.dts) textures.
public class TexCallers extends GhidraScript {
  DecompInterface di;
  PrintWriter pw;
  HashSet<String> done = new HashSet<String>();

  void callersOf(long target, String note, boolean decompile) throws Exception {
    Address ta = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(target);
    pw.println("\n#################### CALLERS OF 0x" + Long.toHexString(target) + "  " + note + " ####################");
    FunctionManager fm = currentProgram.getFunctionManager();
    LinkedHashSet<Function> callers = new LinkedHashSet<Function>();
    for (Reference ref : getReferencesTo(ta)) {
      Function f = fm.getFunctionContaining(ref.getFromAddress());
      if (f != null) callers.add(f);
    }
    for (Function f : callers) {
      pw.println("  caller: " + f.getEntryPoint() + "  " + f.getName());
    }
    if (decompile) {
      for (Function f : callers) {
        String key = f.getEntryPoint().toString();
        if (done.contains(key)) continue;
        done.add(key);
        pw.println("\n---------- decompile " + f.getEntryPoint() + " " + f.getName() + " ----------");
        DecompileResults r = di.decompileFunction(f, 60, monitor);
        if (r != null && r.getDecompiledFunction() != null) pw.println(r.getDecompiledFunction().getC());
      }
    }
  }

  public void run() throws Exception {
    di = new DecompInterface(); di.openProgram(currentProgram);
    pw = new PrintWriter(new FileWriter(System.getProperty("user.home")+"/texcallers.txt"));
    callersOf(0x418570L, "GFXBitmap::load(stream)", true);
    callersOf(0x4180c0L, "GFXBitmap::read(stream)", true);
    callersOf(0x415fd0L, "ResourceManager::load(name)", false);
    pw.close();
    println("wrote texcallers.txt");
  }
}
