// Vtable for TeamObjectiveEvent is at 0x0060fa0c (slot0 = dtor FUN_0040e4e4). Force-disassemble each
// slot target and decompile, so we can read pack()/unpack() (the slots calling BitStream read/write).
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.app.decompiler.*;

public class DumpVtable extends GhidraScript {
  public void run() throws Exception {
    Memory mem = currentProgram.getMemory();
    FunctionManager fm = currentProgram.getFunctionManager();
    AddressSpace sp = currentProgram.getAddressFactory().getDefaultAddressSpace();
    DecompInterface di = new DecompInterface(); di.openProgram(currentProgram);

    long textMin = 0x00401000L, textMax = 0x0060e000L;
    Address vt = sp.getAddress(0x0060fa0cL);
    for (int i = 0; i < 18; i++) {
      Address slotA = vt.add(i * 4L);
      int val;
      try { val = mem.getInt(slotA); } catch (Exception e) { break; }
      long v = val & 0xffffffffL;
      if (v < textMin || v >= textMax) { println(String.format("slot[%2d] = 0x%08x  (not .text -> end of vtable)", i, v)); break; }
      Address pa = sp.getAddress(v);
      Function f = fm.getFunctionAt(pa);
      if (f == null) {
        disassemble(pa);
        f = createFunction(pa, null);
        if (f == null) f = fm.getFunctionContaining(pa);
      }
      println("\n############ slot[" + i + "] @ 0x" + Long.toHexString(v) + (f!=null?(" "+f.getName()):"") + " ############");
      if (f != null) {
        DecompileResults r = di.decompileFunction(f, 45, monitor);
        if (r != null && r.decompileCompleted()) println(r.getDecompiledFunction().getC());
        else println("  <decompile failed>");
      } else println("  <no function>");
    }
  }
}
