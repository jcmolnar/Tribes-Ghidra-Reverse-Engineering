import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.data.*;
import ghidra.app.decompiler.*;
import java.io.*;
import java.util.*;

// Locate ResourceManager::load(const char*,bool) in Tribes.exe 1.40.655 by
// decompiling its callers. TS::Material::load ("...texture '%s'load failed") and the
// HUD loaders ("Unable to load Compass.bmp" / ammoSh.bmp) all call rm.load(name) -
// the common callee is ResourceManager::load. Also dumps resManager.cpp functions to
// bound the region (load itself has no string of its own).
public class FindResLoad extends GhidraScript {
  DecompInterface di;
  PrintWriter pw;
  HashSet<String> done = new HashSet<String>();

  void decompFn(Function f, String note) throws Exception {
    if (f == null) return;
    String key = f.getEntryPoint().toString();
    if (done.contains(key)) return;
    done.add(key);
    pw.println("\n========== " + note + "  entry=" + f.getEntryPoint() + "  name=" + f.getName() + " ==========");
    DecompileResults r = di.decompileFunction(f, 60, monitor);
    if (r != null && r.getDecompiledFunction() != null)
      pw.println(r.getDecompiledFunction().getC());
    pw.println("---- call targets ----");
    Listing lst = currentProgram.getListing();
    InstructionIterator it = lst.getInstructions(f.getBody(), true);
    while (it.hasNext()) {
      Instruction ins = it.next();
      if (!ins.getFlowType().isCall()) continue;
      for (Reference ref : ins.getReferencesFrom()) {
        Address to = ref.getToAddress();
        if (to == null) continue;
        Function tf = getFunctionAt(to);
        pw.println("  " + ins.getAddress() + " CALL " + to + "  " + (tf != null ? tf.getName() : "?"));
      }
    }
  }

  public void run() throws Exception {
    di = new DecompInterface();
    di.openProgram(currentProgram);
    pw = new PrintWriter(new FileWriter(System.getProperty("user.home")+"/resload.txt"));

    String[] anchors = { "Material::load", "Compass.bmp", "ammoSh.bmp", "resManager.cpp" };
    FunctionManager fm = currentProgram.getFunctionManager();

    DataIterator dit = currentProgram.getListing().getDefinedData(true);
    while (dit.hasNext()) {
      Data d = dit.next();
      Object v = d.getValue();
      if (!(v instanceof String)) continue;
      String s = (String) v;
      String hit = null;
      for (String a : anchors) { if (s.contains(a)) { hit = a; break; } }
      if (hit == null) continue;
      pw.println("\n#################### STRING @" + d.getAddress() + " : " + s + " ####################");
      for (Reference ref : getReferencesTo(d.getAddress())) {
        Function f = fm.getFunctionContaining(ref.getFromAddress());
        decompFn(f, "ref-from " + ref.getFromAddress());
      }
    }
    pw.close();
    println("wrote resload.txt");
  }
}
