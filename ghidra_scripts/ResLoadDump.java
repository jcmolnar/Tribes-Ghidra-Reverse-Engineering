import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.app.decompiler.*;
import java.io.*;

// Dump FUN_00415fd0 (resource load-by-name): signature/convention, decompile, the
// first instructions with raw bytes (for the inline-detour prologue), and its callees.
public class ResLoadDump extends GhidraScript {
  DecompInterface di;
  PrintWriter pw;
  AddressSpace sp;

  void dump(long a, String note) throws Exception {
    Address addr = sp.getAddress(a);
    Function f = currentProgram.getFunctionManager().getFunctionContaining(addr);
    pw.println("\n========== 0x" + Long.toHexString(a) + "  " + note + " ==========");
    if (f == null) { pw.println("  (no function)"); return; }
    pw.println("  entry=" + f.getEntryPoint() + "  name=" + f.getName() +
               "  conv=" + f.getCallingConventionName() + "  sig=" + f.getSignature());
    DecompileResults r = di.decompileFunction(f, 60, monitor);
    if (r != null && r.getDecompiledFunction() != null)
      pw.println(r.getDecompiledFunction().getC());

    pw.println("---- first instructions (addr : bytes : mnemonic) ----");
    Listing lst = currentProgram.getListing();
    InstructionIterator it = lst.getInstructions(f.getEntryPoint(), true);
    int n = 0;
    while (it.hasNext() && n < 12) {
      Instruction ins = it.next();
      byte[] b = ins.getBytes();
      StringBuilder hx = new StringBuilder();
      for (byte x : b) hx.append(String.format("%02x ", x & 0xff));
      pw.println("  " + ins.getAddress() + " : " + String.format("%-26s", hx.toString()) + ": " + ins.toString());
      n++;
    }
    pw.println("---- call targets ----");
    InstructionIterator it2 = lst.getInstructions(f.getBody(), true);
    while (it2.hasNext()) {
      Instruction ins = it2.next();
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
    sp = currentProgram.getAddressFactory().getDefaultAddressSpace();
    di = new DecompInterface(); di.openProgram(currentProgram);
    pw = new PrintWriter(new FileWriter("C:\\Users\\Joe\\Desktop\\Tribes Browser Based\\re\\resloaddump.txt"));
    dump(0x415fd0L, "load-by-name (FUN_00415fd0)");
    dump(0x415850L, "unlock/free (FUN_00415850)");
    pw.close();
    println("wrote resloaddump.txt");
  }
}
