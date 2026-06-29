// Decompile TeamObjectiveEvent::pack (0x40a5a8) — must mirror unpack; clarifies field meaning.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.app.decompiler.*;
public class DumpPack extends GhidraScript {
  public void run() throws Exception {
    AddressSpace sp=currentProgram.getAddressFactory().getDefaultAddressSpace();
    FunctionManager fm=currentProgram.getFunctionManager();
    DecompInterface di=new DecompInterface(); di.openProgram(currentProgram);
    long[] addrs={0x0040a5a8L};
    for(long v: addrs){
      Address pa=sp.getAddress(v); Function f=fm.getFunctionAt(pa);
      if(f==null){disassemble(pa); f=createFunction(pa,null);}
      println("\n#### pack @0x"+Long.toHexString(v)+" ####");
      DecompileResults r=di.decompileFunction(f,60,monitor);
      println(r!=null&&r.decompileCompleted()?r.getDecompiledFunction().getC():"<fail>");
    }
  }
}
