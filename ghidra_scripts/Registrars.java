// Registrars — decompile the engine command registrar FUN_005f5590 (behind addCommand 0x5f40d8) and
// FUN_005f56bc, to learn what the 3rd addCommand arg (argInfo) encodes (usage string vs packed
// min/max) and the StringCallback handler type.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.app.decompiler.*;
import java.io.*;

public class Registrars extends GhidraScript {
  public void run() throws Exception {
    AddressSpace sp=currentProgram.getAddressFactory().getDefaultAddressSpace();
    DecompInterface di=new DecompInterface(); di.openProgram(currentProgram);
    PrintWriter pw=new PrintWriter(new BufferedWriter(new FileWriter(
      "C:\\Users\\Joe\\Desktop\\Tribes Browser Based\\re\\registrars.txt")));
    for(long va: new long[]{0x5f5590L,0x5f56bcL}){
      Function f=currentProgram.getFunctionManager().getFunctionContaining(sp.getAddress(va));
      pw.println("===== 0x"+Long.toHexString(va)+(f!=null?" "+f.getName():"")+" =====");
      if(f!=null){ DecompileResults r=di.decompileFunction(f,60,monitor);
        if(r!=null&&r.decompileCompleted()){ String c=r.getDecompiledFunction().getC();
          pw.println(c.length()>3000?c.substring(0,3000):c); } }
    }
    pw.close(); println("wrote re/registrars.txt");
  }
}
