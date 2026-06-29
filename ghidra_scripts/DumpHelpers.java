// Decompile the BitStream/unpack helper functions so we can identify + name them.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.app.decompiler.*;

public class DumpHelpers extends GhidraScript {
  AddressSpace sp; DecompInterface di; FunctionManager fm;
  void deco(long v,String tag){
    Address pa=sp.getAddress(v); Function f=fm.getFunctionAt(pa); if(f==null)f=fm.getFunctionContaining(pa);
    if(f==null){try{disassemble(pa);f=createFunction(pa,null);}catch(Exception e){}}
    println("\n################ "+tag+" @0x"+Long.toHexString(v)+" ################");
    if(f==null){println("  <no func>");return;}
    DecompileResults r=di.decompileFunction(f,60,monitor);
    println(r!=null&&r.decompileCompleted()?r.getDecompiledFunction().getC():"  <fail>");
  }
  public void run() throws Exception {
    sp=currentProgram.getAddressFactory().getDefaultAddressSpace();
    fm=currentProgram.getFunctionManager(); di=new DecompInterface(); di.openProgram(currentProgram);
    deco(0x00582f70L,"readInt? (dominant, 92x)");
    deco(0x00582ea8L,"readBits raw (called by readInt)");
    deco(0x00588db8L,"helper2 (5x)");
    deco(0x00582fe4L,"helper3 (2x)");
    deco(0x00583184L,"helper4 (1x)");
    deco(0x005adc84L,"helper5 (1x)");
    deco(0x0055199cL,"guard (Parent::unpack?, 17x)");
  }
}
