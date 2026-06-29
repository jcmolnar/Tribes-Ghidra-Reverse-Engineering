// V7f — decompile every function in [0x4c1c00, 0x4c3600] (ScoreListCtrl method region) + disasm,
// to locate onPreRender (tabStops scan + 640 terminator + qsort) and onRenderCell.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.app.decompiler.*;
import java.io.*;
import java.util.*;

public class V7f extends GhidraScript {
  PrintWriter pw; DecompInterface di; AddressSpace sp;
  String deco(Function f) {
    DecompileResults r = di.decompileFunction(f, 120, monitor);
    return (r!=null && r.decompileCompleted()) ? r.getDecompiledFunction().getC() : "  <decompile fail>";
  }
  void disasm(Function f) {
    InstructionIterator it = currentProgram.getListing().getInstructions(f.getBody(), true);
    while (it.hasNext()) {
      Instruction ins = it.next();
      StringBuilder b = new StringBuilder();
      try { for (byte x : ins.getBytes()) b.append(String.format("%02x ", x&0xff)); } catch(Exception e){}
      pw.println(String.format("    0x%08x  %-22s %s", ins.getAddress().getOffset(), b.toString().trim(), ins.toString()));
    }
  }
  public void run() throws Exception {
    sp = currentProgram.getAddressFactory().getDefaultAddressSpace();
    di = new DecompInterface(); di.openProgram(currentProgram);
    pw = new PrintWriter(new BufferedWriter(new FileWriter(
        "C:\\Users\\Joe\\Desktop\\Tribes Browser Based\\re\\v7f.txt")));
    long lo=0x4c1c00L, hi=0x4c3600L;
    FunctionIterator fit = currentProgram.getFunctionManager().getFunctions(sp.getAddress(lo), true);
    List<Function> fns=new ArrayList<Function>();
    while (fit.hasNext()){ Function f=fit.next(); long a=f.getEntryPoint().getOffset(); if(a>hi)break; if(a>=lo) fns.add(f); }
    pw.println("functions in ["+Long.toHexString(lo)+","+Long.toHexString(hi)+"]: "+fns.size());
    for (Function f: fns){
      pw.println("\n================================================================");
      pw.println("FUN_"+String.format("%08x",f.getEntryPoint().getOffset())+"  size="+f.getBody().getNumAddresses());
      pw.println("---- decompile ----");
      pw.println(deco(f));
    }
    pw.close();
    println("wrote re/v7f.txt; fns="+fns.size());
  }
}
