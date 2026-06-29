// T1Loop — find the dedicated-server loop: it reads sg.currentTime (DAT_006a841c) and sg.timeBase
// (DAT_006a8420), forms (cur-base)*0.001, and calls SimManager::advanceToTime. Decompile every
// referencer of those globals to pin the loop + advanceToTime + the call site (hook point).
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.app.decompiler.*;
import java.io.*;
import java.util.*;

public class T1Loop extends GhidraScript {
  public void run() throws Exception {
    AddressSpace sp=currentProgram.getAddressFactory().getDefaultAddressSpace();
    Listing lst=currentProgram.getListing();
    FunctionManager fm=currentProgram.getFunctionManager();
    ReferenceManager rm=currentProgram.getReferenceManager();
    DecompInterface di=new DecompInterface(); di.openProgram(currentProgram);
    PrintWriter pw=new PrintWriter(new BufferedWriter(new FileWriter(
      System.getProperty("user.home")+"/t1loop.txt")));
    long[] globals={0x6a841cL,0x6a8420L,0x6a842cL};
    Set<Function> fns=new LinkedHashSet<>();
    for(long g:globals){
      pw.println("refs to 0x"+Long.toHexString(g)+":");
      ReferenceIterator it=rm.getReferencesTo(sp.getAddress(g));
      while(it.hasNext()){ Reference r=it.next(); Function f=fm.getFunctionContaining(r.getFromAddress());
        if(f!=null){ fns.add(f); pw.println("  0x"+Long.toHexString(r.getFromAddress().getOffset())+" in "+f.getName()+" @0x"+Long.toHexString(f.getEntryPoint().getOffset())); } }
    }
    pw.println("\n===== decompiles of referencers (find the (cur-base)*0.001 -> advanceToTime loop) =====");
    for(Function f: fns){
      if(f.getBody().getNumAddresses()>6000) continue;
      DecompileResults r=di.decompileFunction(f,80,monitor); if(r==null||!r.decompileCompleted()) continue;
      String c=r.getDecompiledFunction().getC();
      // server loop: references both 6a841c and 6a8420 (cur & base), or does *0.001 + a thiscall on 6a842c
      if(c.contains("6a841c")||c.contains("6a8420")||c.contains("DAT_006a841c")||c.contains("DAT_006a8420")){
        pw.println("\n----- "+f.getName()+" @0x"+Long.toHexString(f.getEntryPoint().getOffset())+" (size "+f.getBody().getNumAddresses()+") -----");
        pw.println(c.length()>3000?c.substring(0,3000):c);
      }
    }
    pw.close(); println("wrote re/t1loop.txt");
  }
}
