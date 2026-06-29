import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.mem.*;
import ghidra.app.decompiler.*;
import java.io.*;

// Find SimGuiPlugin::consoleCallback via the vtable containing init (FUN_0054aac0),
// decompile it + the cursor (id 0xf..0x13) handling to locate the canvas cursor
// position + on-flag the engine actually uses for its GUI cursor.
public class HudbotCursor2 extends GhidraScript {
  DecompInterface di; PrintWriter pw;
  AddressSpace sp;

  void decomp(long addr, String note) throws Exception {
    Function f = currentProgram.getFunctionManager().getFunctionContaining(sp.getAddress(addr));
    pw.println("\n===== " + note + " 0x" + Long.toHexString(addr) +
               (f != null ? ("  fn=" + f.getEntryPoint()) : " (no fn)") + " =====");
    if (f == null) return;
    DecompileResults r = di.decompileFunction(f, 90, monitor);
    if (r != null && r.getDecompiledFunction() != null) pw.println(r.getDecompiledFunction().getC());
  }

  public void run() throws Exception {
    sp = currentProgram.getAddressFactory().getDefaultAddressSpace();
    di = new DecompInterface(); di.openProgram(currentProgram);
    pw = new PrintWriter(new FileWriter(System.getProperty("user.home")+"/hudbot_cursor2.txt"));
    Memory mem = currentProgram.getMemory();

    // 1) find the vtable: a .rdata pointer whose value == 0x0054aac0 (init)
    long initAddr = 0x0054aac0L;
    Address found = null;
    for (Reference rf : getReferencesToAddr(sp.getAddress(initAddr))) {
      Address from = rf.getFromAddress();
      MemoryBlock b = mem.getBlock(from);
      if (b != null && !b.isExecute()) { found = from; break; }   // data ref = vtable slot
    }
    pw.println("init in vtable slot at: " + found);
    if (found != null) {
      // dump 12 vtable slots around it (some before, several after)
      Address base = found.subtract(8);
      pw.println("\n--- vtable slots ---");
      for (int i = 0; i < 14; i++) {
        Address slot = base.add(i * 4);
        long val = mem.getInt(slot) & 0xFFFFFFFFL;
        pw.println("  [" + slot + "] -> 0x" + Long.toHexString(val));
      }
      // consoleCallback is typically the slot right after init or a nearby one;
      // decompile the few slots after init.
      for (int i = 1; i <= 3; i++) {
        long val = mem.getInt(found.add(i * 4)) & 0xFFFFFFFFL;
        if (val > 0x401000 && val < 0x6e0000) decomp(val, "vtable+" + i);
      }
    }

    // 2) also decompile the SimGuiPlugin module neighbours that likely hold the
    //    cursor handling + the mouse->cursor update.
    pw.close();
    println("wrote hudbot_cursor2.txt");
  }

  ghidra.program.model.symbol.Reference[] getReferencesToAddr(Address a) {
    java.util.List<ghidra.program.model.symbol.Reference> l = new java.util.ArrayList<>();
    ReferenceIterator ri = currentProgram.getReferenceManager().getReferencesTo(a);
    while (ri.hasNext()) l.add(ri.next());
    return l.toArray(new ghidra.program.model.symbol.Reference[0]);
  }
}
