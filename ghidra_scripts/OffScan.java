import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.app.decompiler.*;
import java.io.*;
import java.util.*;

// Find the engine's mouse handler: functions that reference >=2 of the SimCanvas
// cursor offsets (0x1ac on-flag, 0x1b0 buttons, 0x1f8/0x1fc cursor x/y). Then
// decompile them so we can hook the real click path instead of polling.
public class OffScan extends GhidraScript {
  public void run() throws Exception {
    String[] needles = {"0x1ac", "0x1b0", "0x1f8", "0x1fc"};
    Map<Function, Set<String>> hits = new HashMap<>();
    InstructionIterator it = currentProgram.getListing().getInstructions(true);
    long n = 0;
    while (it.hasNext()) {
      Instruction ins = it.next();
      String s = ins.toString();
      if (s.indexOf("0x1") < 0) continue;
      for (String nd : needles) {
        if (s.contains(nd + "]")) {     // memory operand displacement
          Function f = getFunctionContaining(ins.getAddress());
          if (f != null) hits.computeIfAbsent(f, k -> new HashSet<>()).add(nd);
        }
      }
      n++;
    }
    DecompInterface di = new DecompInterface(); di.openProgram(currentProgram);
    PrintWriter pw = new PrintWriter(new FileWriter(System.getProperty("user.home")+"/offscan.txt"));
    pw.println("scanned " + n + " instructions");
    // candidates = functions touching >=2 of the offsets
    List<Function> cand = new ArrayList<>();
    for (Map.Entry<Function, Set<String>> e : hits.entrySet())
      if (e.getValue().size() >= 2) cand.add(e.getKey());
    pw.println("candidates (>=2 cursor offsets): " + cand.size());
    for (Function f : cand)
      pw.println("  " + f.getEntryPoint() + " " + f.getName() + " -> " + hits.get(f));
    // decompile each candidate
    for (Function f : cand) {
      pw.println("\n\n======== " + f.getEntryPoint() + " " + f.getName() + " ========");
      DecompileResults r = di.decompileFunction(f, 90, monitor);
      if (r != null && r.getDecompiledFunction() != null) pw.println(r.getDecompiledFunction().getC());
    }
    pw.close();
    println("wrote offscan.txt (" + cand.size() + " candidates)");
  }
}
