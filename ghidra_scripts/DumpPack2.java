// Decompile the REAL TeamObjectiveEvent::PACK (0x40a434, server write side = the wire format the wasm client
// must read) plus the write helpers so we can read widths. FUN_00582fa0=writeInt(val,bits),
// FUN_00582e58=writeFlag, vtable+0x28 on the stream = writeString.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.app.decompiler.*;
public class DumpPack2 extends GhidraScript {
  AddressSpace sp; DecompInterface di; FunctionManager fm;
  void deco(long v,String t){
    Address pa=sp.getAddress(v); Function f=fm.getFunctionAt(pa); if(f==null)f=fm.getFunctionContaining(pa);
    if(f==null){ try{disassemble(pa); f=createFunction(pa,null);}catch(Exception e){} }
    println("\n#### "+t+" @0x"+Long.toHexString(v)+" ####");
    if(f==null){println("  <no func>");return;}
    DecompileResults r=di.decompileFunction(f,60,monitor);
    println(r!=null&&r.decompileCompleted()?r.getDecompiledFunction().getC():"<fail>");
  }
  public void run() throws Exception {
    sp=currentProgram.getAddressFactory().getDefaultAddressSpace();
    fm=currentProgram.getFunctionManager(); di=new DecompInterface(); di.openProgram(currentProgram);
    deco(0x0040a434L, "REAL TeamObjectiveEvent::pack (server write side)");
    deco(0x00582fa0L, "writeInt(val,bits)?");
    deco(0x00582e58L, "writeFlag?");
  }
}
