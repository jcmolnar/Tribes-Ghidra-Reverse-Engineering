// FGSlider140 — dump FearGui::FGSlider's vtable (0x0065532c) in 1.40 Tribes.exe (MSVC, clean),
// decompile every slot, and follow into the persist read()/write() (the slots that call the
// StreamIO read/write at obj-vtbl +0x18/+0x1c). Goal: exact on-disk field layout of an 'FGsk'
// block. Output: re/fgslider140.txt
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.app.decompiler.*;
import java.io.*;

public class FGSlider140 extends GhidraScript {
  Memory mem; FunctionManager fm; AddressSpace sp; DecompInterface di; PrintWriter pw;
  long textMin = 0x00401000L, textMax = 0x00700000L;

  String decomp(long va) {
    try {
      Address pa = sp.getAddress(va);
      Function f = fm.getFunctionAt(pa);
      if (f == null) { disassemble(pa); f = createFunction(pa, null); if (f==null) f = fm.getFunctionContaining(pa); }
      if (f == null) return "  <no function @0x"+Long.toHexString(va)+">";
      DecompileResults r = di.decompileFunction(f, 60, monitor);
      if (r!=null && r.decompileCompleted()) return r.getDecompiledFunction().getC();
      return "  <decompile failed @0x"+Long.toHexString(va)+">";
    } catch (Exception e) { return "  <exc "+e+">"; }
  }

  void dumpVtable(String label, long vtVA, int slots) throws Exception {
    pw.println("\n==================================================================");
    pw.println("  " + label + "  vtable=0x" + Long.toHexString(vtVA));
    pw.println("==================================================================");
    for (int i = 0; i < slots; i++) {
      long v;
      try { v = mem.getInt(sp.getAddress(vtVA + i*4L)) & 0xffffffffL; } catch (Exception e) { break; }
      if (v < textMin || v >= textMax) { pw.println("slot["+i+"] = 0x"+Long.toHexString(v)+" (end)"); break; }
      Function f = fm.getFunctionAt(sp.getAddress(v));
      pw.println("\n---- slot["+i+"] @ 0x"+Long.toHexString(v)+(f!=null?(" "+f.getName()):"")+" ----");
      pw.println(decomp(v));
    }
  }

  public void run() throws Exception {
    mem = currentProgram.getMemory();
    fm = currentProgram.getFunctionManager();
    sp = currentProgram.getAddressFactory().getDefaultAddressSpace();
    di = new DecompInterface(); di.openProgram(currentProgram);
    pw = new PrintWriter(new BufferedWriter(new FileWriter(
        "C:\\Users\\Joe\\Desktop\\Tribes Browser Based\\re\\fgslider140.txt")));

    // FGSlider RTTI vtable per full_catalog_140. The C++ object vtable pointer usually sits a few
    // bytes after the RTTI complete-object-locator; try the catalog address and a couple offsets.
    dumpVtable("FearGui::FGSlider (catalog 0x0065532c)", 0x0065532cL, 40);
    pw.close();
    println("wrote re/fgslider140.txt");
  }
}
