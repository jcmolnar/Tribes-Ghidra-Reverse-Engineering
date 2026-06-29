// FUN_0040e4e4 is the TeamObjectiveEvent deleting-destructor (vtable slot 0). Find the vtable that
// contains it, dump the slots, and decompile each to locate unpack() (the one reading the BitStream).
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.mem.*;
import ghidra.app.decompiler.*;

public class FindVtable extends GhidraScript {
  DecompInterface di;
  AddressSpace sp;
  Memory mem;
  FunctionManager fm;

  Address mkAddr(int val) { return sp.getAddress(val & 0xffffffffL); }

  String decompile(Address entry) {
    Function f = fm.getFunctionAt(entry);
    if (f == null) f = fm.getFunctionContaining(entry);
    if (f == null) return "  [no function]";
    DecompileResults r = di.decompileFunction(f, 45, monitor);
    if (r != null && r.decompileCompleted()) return r.getDecompiledFunction().getC();
    return "  <decompile failed>";
  }

  public void run() throws Exception {
    mem = currentProgram.getMemory();
    fm = currentProgram.getFunctionManager();
    ReferenceManager rm = currentProgram.getReferenceManager();
    sp = currentProgram.getAddressFactory().getDefaultAddressSpace();
    di = new DecompInterface(); di.openProgram(currentProgram);

    Address dtor = mkAddr(0x0040e4e4);
    println("=== references to dtor FUN_0040e4e4 ===");
    ReferenceIterator it = rm.getReferencesTo(dtor);
    java.util.List<Address> vtables = new java.util.ArrayList<Address>();
    while (it.hasNext()) {
      Reference r = it.next();
      Address from = r.getFromAddress();
      Function fc = fm.getFunctionContaining(from);
      String where = (fc != null) ? ("code in " + fc.getName()) : "DATA (vtable?)";
      println("  ref from " + from + "  [" + where + "]  type=" + r.getReferenceType());
      if (fc == null) vtables.add(from);
    }
    // Fallback: brute-scan .text/.rdata for the literal pointer if Ghidra tracked no data ref.
    if (vtables.isEmpty()) {
      println("  (no tracked data ref; brute-scanning for pointer bytes)");
      byte[] le = new byte[]{(byte)0xe4,(byte)0xe4,0x40,0x00};
      Address a = mem.findBytes(currentProgram.getMinAddress(), le, null, true, monitor);
      while (a != null) {
        Function fc = fm.getFunctionContaining(a);
        if (fc == null) { println("  raw ptr at " + a); vtables.add(a); }
        a = mem.findBytes(a.add(1), le, null, true, monitor);
        if (vtables.size() > 8) break;
      }
    }

    // For each candidate vtable location, the vtable likely STARTS at this slot (dtor is slot 0).
    for (Address vt : vtables) {
      println("\n=== VTABLE @ " + vt + " (dumping 16 slots) ===");
      for (int i = 0; i < 16; i++) {
        Address slotA = vt.add(i * 4L);
        int val;
        try { val = mem.getInt(slotA); } catch (Exception e) { break; }
        Address pa = mkAddr(val);
        Function f = fm.getFunctionAt(pa);
        if (f == null) f = fm.getFunctionContaining(pa);
        println(String.format("  slot[%2d] %s = 0x%08x -> %s", i, slotA, val, f != null ? f.getName() : "(not a func / end)"));
        if (f == null) break;
      }
    }
  }
}
