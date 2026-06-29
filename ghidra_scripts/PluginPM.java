// PluginPM — decompile the user's PlayerManagerPlugin.dll command handlers (getFreeId / isIdFree)
// to recover EXACTLY how the client free-list is read: the manager global, the offset, and the
// free-list structure. This is ground truth for building the expanded plugin.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.app.decompiler.*;
import java.io.*;
import java.util.*;

public class PluginPM extends GhidraScript {
  public void run() throws Exception {
    Listing lst=currentProgram.getListing();
    FunctionManager fm=currentProgram.getFunctionManager();
    ReferenceManager rm=currentProgram.getReferenceManager();
    DecompInterface di=new DecompInterface(); di.openProgram(currentProgram);
    PrintWriter pw=new PrintWriter(new BufferedWriter(new FileWriter(
      "C:\\Users\\Joe\\Desktop\\Tribes Browser Based\\re\\pluginpm.txt")));
    // anchor on the command-name strings the plugin registers
    Set<Function> fns=new LinkedHashSet<>();
    DataIterator dit=lst.getDefinedData(true);
    while(dit.hasNext()){ Data d=dit.next(); Object v=d.getValue(); if(!(v instanceof String)) continue; String s=(String)v;
      if(s.contains("FreeId")||s.contains("isIdFree")||s.contains("PlayerManager")||s.contains("getFree")){
        pw.println("str @0x"+Long.toHexString(d.getAddress().getOffset())+" = \""+s+"\"");
        ReferenceIterator it=rm.getReferencesTo(d.getAddress());
        while(it.hasNext()){ Reference r=it.next(); Function f=fm.getFunctionContaining(r.getFromAddress());
          if(f!=null) fns.add(f); }
      }
    }
    pw.println("\n===== handler decompiles (the free-list access) =====");
    for(Function f: fns){
      pw.println("\n----- "+f.getName()+" @0x"+Long.toHexString(f.getEntryPoint().getOffset())+" -----");
      DecompileResults r=di.decompileFunction(f,60,monitor);
      if(r!=null&&r.decompileCompleted()) pw.println(r.getDecompiledFunction().getC());
    }
    pw.close(); println("wrote re/pluginpm.txt ("+fns.size()+" handlers)");
  }
}
