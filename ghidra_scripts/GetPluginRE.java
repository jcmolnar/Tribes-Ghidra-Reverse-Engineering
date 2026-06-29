// GetPluginRE — decompile ServerSidePlugin's getPlugin export + DllMain to learn how/when a
// Kronos plugin registers its console commands (so PlayerManager registers at the right time).
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.app.decompiler.*;
import java.io.*;
import java.util.*;

public class GetPluginRE extends GhidraScript {
  public void run() throws Exception {
    FunctionManager fm=currentProgram.getFunctionManager();
    SymbolTable st=currentProgram.getSymbolTable();
    DecompInterface di=new DecompInterface(); di.openProgram(currentProgram);
    PrintWriter pw=new PrintWriter(new BufferedWriter(new FileWriter(
      System.getProperty("user.home")+"/getplugin.txt")));
    Set<Function> seen=new LinkedHashSet<>();
    // find getPlugin + DllMain by symbol name
    for(Symbol s: st.getAllSymbols(false)){
      String n=s.getName();
      if(n.equalsIgnoreCase("getPlugin")||n.contains("DllMain")||n.contains("dllmain")){
        Function f=fm.getFunctionContaining(s.getAddress());
        if(f!=null) seen.add(f);
        else pw.println("symbol "+n+" @0x"+Long.toHexString(s.getAddress().getOffset())+" (no func)");
      }
    }
    // also: the entry point
    Address ep=currentProgram.getImageBase();
    pw.println("imageBase=0x"+Long.toHexString(ep.getOffset()));
    for(Function f: seen){
      pw.println("\n========== "+f.getName()+" @0x"+Long.toHexString(f.getEntryPoint().getOffset())+" ==========");
      DecompileResults r=di.decompileFunction(f,70,monitor);
      if(r!=null&&r.decompileCompleted()){ String c=r.getDecompiledFunction().getC();
        pw.println(c.length()>5000?c.substring(0,5000):c);
        // decompile the functions it calls (1 level) — the registration helpers
        for(Function cal: f.getCalledFunctions(monitor)){
          if(cal.getBody().getNumAddresses()>500) continue;
          DecompileResults r2=di.decompileFunction(cal,40,monitor);
          if(r2!=null&&r2.decompileCompleted()){ pw.println("  --- callee "+cal.getName()+" @0x"+Long.toHexString(cal.getEntryPoint().getOffset())+" ---");
            String c2=r2.getDecompiledFunction().getC(); pw.println("  "+(c2.length()>1500?c2.substring(0,1500):c2)); }
        }
      }
    }
    pw.close(); println("wrote re/getplugin.txt ("+seen.size()+" fns)");
  }
}
