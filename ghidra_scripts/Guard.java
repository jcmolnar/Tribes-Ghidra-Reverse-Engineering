// Does the unpack guard FUN_0055199c consume bitstream bits? (= leading field our mirror must read).
// Also dump TeamObjectiveEvent::pack (FUN_0040a5a8) fully for the symmetric write side, and the
// persistent TAG: the event's wire classTag (EventManager reads readInt(7)+1024). Look for where the
// objective class is registered with its tag.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.app.decompiler.*;

public class Guard extends GhidraScript {
  AddressSpace sp; DecompInterface di; FunctionManager fm;
  void deco(long v,String tag){ Address pa=sp.getAddress(v); Function f=fm.getFunctionAt(pa); if(f==null)f=fm.getFunctionContaining(pa);
    if(f==null){try{disassemble(pa);f=createFunction(pa,null);}catch(Exception e){}}
    println("\n################ "+tag+" @0x"+Long.toHexString(v)+" ################");
    if(f==null){println("  <no func>");return;}
    DecompileResults r=di.decompileFunction(f,50,monitor);
    println(r!=null&&r.decompileCompleted()?r.getDecompiledFunction().getC():"  <fail>"); }
  public void run() throws Exception {
    sp=currentProgram.getAddressFactory().getDefaultAddressSpace();
    fm=currentProgram.getFunctionManager(); di=new DecompInterface(); di.openProgram(currentProgram);
    deco(0x0055199cL,"FUN_0055199c (unpack guard - consumes bits?)");
    deco(0x00588db8L,"FUN_00588db8 (readString?)");
  }
}
