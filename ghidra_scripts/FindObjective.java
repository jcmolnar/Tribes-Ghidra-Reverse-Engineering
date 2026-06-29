// Locate TeamObjectiveEvent's persistent descriptor, resolve its pointers (create fn / vtable),
// and decompile candidate functions to read the unpack() bit layout.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.mem.*;
import ghidra.app.decompiler.*;

public class FindObjective extends GhidraScript {
  DecompInterface di;
  AddressSpace sp;

  Address mkAddr(int val) { return sp.getAddress(val & 0xffffffffL); }

  void decompile(Address entry, String tag) {
    Function f = currentProgram.getFunctionManager().getFunctionAt(entry);
    if (f == null) f = currentProgram.getFunctionManager().getFunctionContaining(entry);
    if (f == null) { println("  [no function at " + entry + " for " + tag + "]"); return; }
    DecompileResults r = di.decompileFunction(f, 60, monitor);
    println("==== DECOMPILE " + tag + "  " + f.getName() + " @ " + f.getEntryPoint() + " ====");
    if (r != null && r.decompileCompleted()) println(r.getDecompiledFunction().getC());
    else println("  <decompile failed>");
  }

  public void run() throws Exception {
    Memory mem = currentProgram.getMemory();
    FunctionManager fm = currentProgram.getFunctionManager();
    ReferenceManager rm = currentProgram.getReferenceManager();
    sp = currentProgram.getAddressFactory().getDefaultAddressSpace();
    di = new DecompInterface(); di.openProgram(currentProgram);

    Address found = mem.findBytes(currentProgram.getMinAddress(),
        "TeamObjectiveEvent".getBytes("ASCII"), null, true, monitor);
    println("string 'TeamObjectiveEvent' at " + found);
    if (found == null) return;

    // 1) Dump the descriptor window: read every 4-byte word from name-40 .. name+8 and resolve.
    println("--- descriptor words around the name ---");
    for (long d = -40; d <= 8; d += 4) {
      Address a = found.add(d);
      try {
        int val = mem.getInt(a);
        Address pa = mkAddr(val);
        Function fAt = fm.getFunctionAt(pa);
        Function fIn = fm.getFunctionContaining(pa);
        String what = (fAt != null) ? ("FUNC " + fAt.getName())
                    : (fIn != null) ? ("in-func " + fIn.getName() + "+")
                    : (mem.contains(pa) ? "data" : "unmapped");
        println(String.format("  [name%+d] %s = 0x%08x -> %s", d, a, val, what));
      } catch (Exception e) { println("  [name" + d + "] <read err>"); }
    }

    // 2) Any references to the descriptor base region (the registration callsite).
    println("--- references into name-48..name ---");
    for (long d = -48; d <= 0; d += 4) {
      Address a = found.add(d);
      ReferenceIterator it = rm.getReferencesTo(a);
      while (it.hasNext()) {
        Reference r = it.next();
        Function f = fm.getFunctionContaining(r.getFromAddress());
        println("  REF -> " + a + " from " + r.getFromAddress() + " in " + (f != null ? f.getName() : "?"));
      }
    }

    // 3) Decompile the function pointer that sits right before the name (seen in recon: a real fn).
    try {
      int beforePtr = mem.getInt(found.add(-32)); // sweep a few candidate slots below
    } catch (Exception e) {}
    for (long d = -36; d <= -4; d += 4) {
      Address a = found.add(d);
      try {
        int val = mem.getInt(a);
        Address pa = mkAddr(val);
        if (fm.getFunctionAt(pa) != null) decompile(pa, "descr-ptr[name" + d + "]");
      } catch (Exception e) {}
    }
  }
}
