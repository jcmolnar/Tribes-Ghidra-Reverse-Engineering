// CallersTex — find callers of the interior render-traversal + surface-binner seeds, decompile each
// caller (the render orchestrator + the bin-flush/draw where the per-surface texture bind lives).
// Output: re/callerstex.txt
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.app.decompiler.*;
import java.io.*;
import java.util.*;

public class CallersTex extends GhidraScript {
  PrintWriter pw; DecompInterface di; AddressSpace sp; FunctionManager fm;
  String decomp(Function f){
    if(f==null) return "  <no fn>";
    DecompileResults r=di.decompileFunction(f,90,monitor);
    return "FUN_"+Long.toHexString(f.getEntryPoint().getOffset())+" (size "+f.getBody().getNumAddresses()+"):\n"
      +((r!=null&&r.decompileCompleted())?r.getDecompiledFunction().getC():"<decompile fail>");
  }
  public void run() throws Exception {
    sp=currentProgram.getAddressFactory().getDefaultAddressSpace();
    fm=currentProgram.getFunctionManager();
    di=new DecompInterface(); di.openProgram(currentProgram);
    pw=new PrintWriter(new BufferedWriter(new FileWriter(System.getProperty("user.home")+"/callerstex.txt")));
    long[] seeds={0x4833f0L,0x4834c0L,0x4fb4ccL};
    Set<Long> seen=new LinkedHashSet<Long>();
    for(long s:seeds){
      pw.println("\n#################### CALLERS OF 0x"+Long.toHexString(s)+" ####################");
      ReferenceIterator it=currentProgram.getReferenceManager().getReferencesTo(sp.getAddress(s));
      while(it.hasNext()){
        Reference r=it.next();
        if(!r.getReferenceType().isCall()) continue;
        Function f=fm.getFunctionContaining(r.getFromAddress());
        if(f==null) continue;
        long fa=f.getEntryPoint().getOffset();
        pw.println("  caller 0x"+Long.toHexString(r.getFromAddress().getOffset())+" in FUN_"+Long.toHexString(fa));
        if(seen.add(fa)){
          pw.println(decomp(f));
        }
      }
    }
    pw.close();
    println("wrote re/callerstex.txt; callers="+seen);
  }
}
