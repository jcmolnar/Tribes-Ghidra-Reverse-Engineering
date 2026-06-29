// FindLoader — find T1Vista's plugin loader: it GetProcAddress's "getPlugin", calls it, and walks
// the returned descriptor's command table to register commands. Decompiling it gives the EXACT
// descriptor + command-table format the PlayerManager DLL must return.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.app.decompiler.*;
import java.io.*;
import java.util.*;

public class FindLoader extends GhidraScript {
  public void run() throws Exception {
    Listing lst=currentProgram.getListing();
    FunctionManager fm=currentProgram.getFunctionManager();
    ReferenceManager rm=currentProgram.getReferenceManager();
    DecompInterface di=new DecompInterface(); di.openProgram(currentProgram);
    PrintWriter pw=new PrintWriter(new BufferedWriter(new FileWriter(
      System.getProperty("user.home")+"/loader.txt")));
    Set<Function> fns=new LinkedHashSet<>();
    DataIterator dit=lst.getDefinedData(true);
    while(dit.hasNext()){ Data d=dit.next(); Object v=d.getValue(); if(!(v instanceof String)) continue; String s=(String)v;
      if(s.equals("getPlugin")||s.contains("PluginLoader")||s.contains("loadPlugin")||(s.contains("Plugins")&&s.contains("\\"))||s.contains(".dll")){
        ReferenceIterator it=rm.getReferencesTo(d.getAddress());
        while(it.hasNext()){ Reference r=it.next(); Function f=fm.getFunctionContaining(r.getFromAddress());
          if(f!=null){ fns.add(f); pw.println("\""+s+"\" <- 0x"+Long.toHexString(r.getFromAddress().getOffset())+" in "+f.getName()+" @0x"+Long.toHexString(f.getEntryPoint().getOffset())); } }
      }
    }
    pw.println("\n===== loader decompiles (look for GetProcAddress(getPlugin) + descriptor walk) =====");
    for(Function f: fns){
      // the loader references "getPlugin" + GetProcAddress; prioritize those
      pw.println("\n----- "+f.getName()+" @0x"+Long.toHexString(f.getEntryPoint().getOffset())+" (size "+f.getBody().getNumAddresses()+") -----");
      DecompileResults r=di.decompileFunction(f,80,monitor);
      if(r!=null&&r.decompileCompleted()){ String c=r.getDecompiledFunction().getC();
        pw.println(c.length()>6000?c.substring(0,6000):c); }
    }
    pw.close(); println("wrote re/loader.txt ("+fns.size()+" fns)");
  }
}
