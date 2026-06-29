import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.*;
import ghidra.app.decompiler.*;
import java.io.*;
import java.util.*;

// cursorOn = FUN_00540670 sets canvas+0x1ac. Find the vtable(s) that contain it
// (the canvas class), then decompile every method of that class, flagging the
// ones that touch param_1+0x1b0 / +0x1f8 (the mouse-button / cursor handler).
public class FindMouse extends GhidraScript {
  public void run() throws Exception {
    AddressSpace sp = currentProgram.getAddressFactory().getDefaultAddressSpace();
    Memory mem = currentProgram.getMemory();
    DecompInterface di = new DecompInterface(); di.openProgram(currentProgram);
    PrintWriter pw = new PrintWriter(new FileWriter(System.getProperty("user.home")+"/findmouse.txt"));

    long cursorOn = 0x00540670L;
    // 1) find data refs to cursorOn (vtable slots)
    List<Address> vslots = new ArrayList<>();
    ReferenceIterator ri = currentProgram.getReferenceManager().getReferencesTo(sp.getAddress(cursorOn));
    while (ri.hasNext()) {
      Reference rf = ri.next();
      MemoryBlock b = mem.getBlock(rf.getFromAddress());
      if (b != null && !b.isExecute()) vslots.add(rf.getFromAddress());
    }
    pw.println("cursorOn vtable slots: " + vslots);

    // 2) for each vtable, scan its slots and decompile methods touching +0x1b0/+0x1f8
    Set<Long> done = new HashSet<>();
    for (Address slot : vslots) {
      // walk back to a plausible vtable start: scan up to 60 slots forward from slot-0x40
      Address base = slot.subtract(0x80);
      pw.println("\n==== vtable near " + slot + " (base " + base + ") ====");
      for (int i = 0; i < 80; i++) {
        Address s = base.add(i * 4);
        long fn;
        try { fn = mem.getInt(s) & 0xFFFFFFFFL; } catch (Exception e) { break; }
        if (fn < 0x401000 || fn > 0x6e0000) continue;
        if (!done.add(fn)) continue;
        Function f = currentProgram.getFunctionManager().getFunctionContaining(sp.getAddress(fn));
        if (f == null) continue;
        DecompileResults r = di.decompileFunction(f, 50, monitor);
        if (r == null || r.getDecompiledFunction() == null) continue;
        String c = r.getDecompiledFunction().getC();
        if (c.contains("+ 0x1b0") || c.contains("+ 0x1f8") || c.contains("+ 0x1b4")
            || c.contains("+ 0x1ac") || c.contains("+ 0x1f0")) {
          pw.println("\n-------- vtable[~" + i + "] 0x" + Long.toHexString(fn) + " --------");
          pw.println(c);
        }
      }
    }
    pw.close();
    println("wrote findmouse.txt");
  }
}
