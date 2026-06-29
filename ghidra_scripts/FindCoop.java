// FindCoop — decompile every function in the input region and report ones that call a device
// vtable method at +0x34 (SetCooperativeLevel) or +0x1c (Acquire), with the flag constant, so we
// can find capture() and the EXCLUSIVE cooperative-level value to patch. Output: re/coop_re.txt
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.app.decompiler.*;
import java.io.*;

public class FindCoop extends GhidraScript {
  public void run() throws Exception {
    DecompInterface di=new DecompInterface(); di.openProgram(currentProgram);
    FunctionManager fm=currentProgram.getFunctionManager();
    PrintWriter pw=new PrintWriter(new BufferedWriter(new FileWriter(
      System.getProperty("user.home")+"/coop_re.txt")));
    AddressSpace sp=currentProgram.getAddressFactory().getDefaultAddressSpace();
    // input region (DirectInput init FUN_0052bc00 lives here)
    long lo=0x529000L, hi=0x52f000L;
    FunctionIterator it=fm.getFunctions(sp.getAddress(lo), true);
    int hits=0;
    while(it.hasNext()){
      Function f=it.next();
      long a=f.getEntryPoint().getOffset();
      if(a>=hi) break;
      DecompileResults r=di.decompileFunction(f,60,monitor);
      if(r==null||!r.decompileCompleted()) continue;
      String c=r.getDecompiledFunction().getC();
      if(c.contains("+ 0x34))") || c.contains("+ 0x1c))")){
        hits++;
        pw.println("\n================ "+f.getName()+" @0x"+Long.toHexString(a)+" ================");
        // print lines mentioning the vtable cooperative/acquire/dataformat calls + context
        String[] lines=c.split("\n");
        for(int i=0;i<lines.length;i++){
          if(lines[i].contains("+ 0x34))")||lines[i].contains("+ 0x1c))")||lines[i].contains("+ 0x2c))")||lines[i].contains("+ 0x18))")){
            for(int k=Math.max(0,i-1);k<=Math.min(lines.length-1,i+1);k++) pw.println("   "+lines[k]);
            pw.println("   ----");
          }
        }
        // also dump the whole function if it has 0x34 (the capture candidate)
        if(c.contains("+ 0x34))")){ pw.println("---- FULL ----\n"+c); }
        monitor.checkCancelled();
      }
    }
    pw.close();
    println("FindCoop hits="+hits+" -> re/coop_re.txt");
  }
}
