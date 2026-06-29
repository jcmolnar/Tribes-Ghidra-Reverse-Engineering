// Decompile TeamObjectiveEvent pack/unpack (vtable @0x0060f9f4: pack +0c=0x0040a434, unpack +10=0x0040a478)
// plus the neighbouring class (record A @0x0060f9c0: pack 0x0040a5a8 unpack 0x0040a6a0) for comparison,
// and the BitStream helpers so we can label readInt/readString/readFlag widths.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.app.decompiler.*;

public class DecObj extends GhidraScript {
  AddressSpace sp; DecompInterface di; FunctionManager fm;
  void deco(long v, String tag){
    Address pa=sp.getAddress(v); Function f=fm.getFunctionAt(pa); if(f==null)f=fm.getFunctionContaining(pa);
    if(f==null){ try{disassemble(pa); f=createFunction(pa,null);}catch(Exception e){} }
    println("\n################ "+tag+" @ 0x"+Long.toHexString(v)+(f!=null?(" "+f.getName()):"")+" ################");
    if(f==null){ println("  <no func>"); return; }
    DecompileResults r=di.decompileFunction(f,50,monitor);
    println(r!=null&&r.decompileCompleted()? r.getDecompiledFunction().getC():"  <decompile failed>");
  }
  public void run() throws Exception {
    sp=currentProgram.getAddressFactory().getDefaultAddressSpace();
    fm=currentProgram.getFunctionManager();
    di=new DecompInterface(); di.openProgram(currentProgram);
    deco(0x0040a434L, "TeamObjectiveEvent::pack? (vtbl 0x60f9f4 +0c)");
    deco(0x0040a478L, "TeamObjectiveEvent::unpack? (vtbl 0x60f9f4 +10)");
    deco(0x0040a6a0L, "recordA::unpack (vtbl 0x60f9c0 +10)");
    // BitStream helpers
    deco(0x00582fa0L, "helper FUN_00582fa0 (writeInt val,bits ?)");
    deco(0x00582e58L, "helper FUN_00582e58 (writeFlag ?)");
  }
}
