// PluginReg — recover how ServerSidePlugin registers namespaced console commands (Player::setJet
// etc.) on T1Vista, so the PlayerManager DLL can register getFreeId/reserveId/... the same way.
// Anchors on the command-name strings + decompiles the registering function(s).
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.app.decompiler.*;
import java.io.*;
import java.util.*;

public class PluginReg extends GhidraScript {
  public void run() throws Exception {
    Listing lst=currentProgram.getListing();
    FunctionManager fm=currentProgram.getFunctionManager();
    ReferenceManager rm=currentProgram.getReferenceManager();
    DecompInterface di=new DecompInterface(); di.openProgram(currentProgram);
    PrintWriter pw=new PrintWriter(new BufferedWriter(new FileWriter(
      "C:\\Users\\Joe\\Desktop\\Tribes Browser Based\\re\\pluginreg.txt")));
    String[] want={"setJet","getPitch","setGravity","setPitch","ShowAICrash","getGravity","find_path","setSkin"};
    Set<Function> regfns=new LinkedHashSet<>();
    DataIterator dit=lst.getDefinedData(true);
    while(dit.hasNext()){ Data d=dit.next(); Object v=d.getValue(); if(!(v instanceof String)) continue; String s=(String)v;
      boolean m=false; for(String w:want) if(s.equals(w)||s.endsWith("::"+w)||s.contains(w)){m=true;break;}
      if(!m) continue;
      ReferenceIterator it=rm.getReferencesTo(d.getAddress());
      while(it.hasNext()){ Reference r=it.next(); Function f=fm.getFunctionContaining(r.getFromAddress());
        if(f!=null){ regfns.add(f); pw.println("\""+s+"\" @0x"+Long.toHexString(d.getAddress().getOffset())+" <- 0x"+Long.toHexString(r.getFromAddress().getOffset())+" in "+f.getName()); } }
    }
    pw.println("\n===== registering function decompiles (the addCommand pattern) =====");
    for(Function f: regfns){
      pw.println("\n----- "+f.getName()+" @0x"+Long.toHexString(f.getEntryPoint().getOffset())+" -----");
      DecompileResults r=di.decompileFunction(f,60,monitor);
      if(r!=null&&r.decompileCompleted()){ String c=r.getDecompiledFunction().getC();
        pw.println(c.length()>4000?c.substring(0,4000):c); }
    }
    pw.close(); println("wrote re/pluginreg.txt ("+regfns.size()+" fns)");
  }
}
