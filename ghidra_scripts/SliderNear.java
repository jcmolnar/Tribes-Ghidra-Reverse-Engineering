// SliderNear — FGSlider::onAdd is at 0x4c97b0. Borland emits a class's methods contiguously, so
// FGSlider::read (a small fn: read version + numDiscrete, call Parent::read) sits nearby. Decompile
// every function in [0x4c9000, 0x4ca400] with the Borland cspec so we can read the exact field
// widths. Also decompile onAdd. Output: re/slider_near.txt
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.app.decompiler.*;
import java.io.*;
import java.util.*;

public class SliderNear extends GhidraScript {
  public void run() throws Exception {
    AddressSpace sp=currentProgram.getAddressFactory().getDefaultAddressSpace();
    FunctionManager fm=currentProgram.getFunctionManager();
    Listing lst=currentProgram.getListing();
    DecompInterface di=new DecompInterface(); di.openProgram(currentProgram);
    PrintWriter pw=new PrintWriter(new BufferedWriter(new FileWriter(
      "C:\\Users\\Joe\\Desktop\\Tribes Browser Based\\re\\slider_near.txt")));

    long lo=0x004c9000L, hi=0x004ca400L;
    // ensure the range is disassembled + functions created
    LinkedHashSet<Long> fns=new LinkedHashSet<Long>();
    Address a=sp.getAddress(lo);
    while (a.getOffset()<hi) {
      Function f=fm.getFunctionContaining(a);
      if (f==null) { try{ disassemble(a); f=createFunction(a,null);}catch(Exception e){} }
      if (f!=null){ fns.add(f.getEntryPoint().getOffset()); a=f.getBody().getMaxAddress().add(1); }
      else a=a.add(1);
    }
    pw.println("#### functions in [0x4c9000,0x4ca400]: "+fns.size());
    for (Long fa:fns) pw.println("   0x"+Long.toHexString(fa));

    // decompile onAdd explicitly + each near function
    long[] extra={0x4c97b0L};
    for (long e:extra) fns.add(e);
    for (Long fa:fns) {
      Function f=fm.getFunctionContaining(sp.getAddress(fa));
      if (f==null) continue;
      pw.println("\n================ 0x"+Long.toHexString(f.getEntryPoint().getOffset())+" "+f.getName()+" ================");
      try {
        DecompileResults r=di.decompileFunction(f,70,monitor);
        if (r!=null && r.decompileCompleted()) pw.println(r.getDecompiledFunction().getC());
        else pw.println("  <decompile failed>");
      } catch(Exception ex){ pw.println("  <exc "+ex+">"); }
    }
    pw.close(); println("wrote re/slider_near.txt  fns="+fns.size());
  }
}
