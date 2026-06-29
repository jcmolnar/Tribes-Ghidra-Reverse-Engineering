// Crack Persistent::create (FUN_0058afe4) to find the tag->class table, then find what WRITES that table
// (the IMPLEMENT_PERSISTENT_TAG registrations) so we can read T1Vista's ACTUAL tag->class map and compare to
// our FearDcl.h guesses. The objective desync is likely a tag mismatch (create returns the wrong class).
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.app.decompiler.*;

public class DumpCreate extends GhidraScript {
  AddressSpace sp; DecompInterface di; FunctionManager fm;
  void deco(long v,String t){
    Address pa=sp.getAddress(v); Function f=fm.getFunctionAt(pa); if(f==null)f=fm.getFunctionContaining(pa);
    if(f==null){ try{disassemble(pa); f=createFunction(pa,null);}catch(Exception e){} }
    println("\n################ "+t+" @0x"+Long.toHexString(v)+" ################");
    if(f==null){println("  <no func>");return;}
    DecompileResults r=di.decompileFunction(f,90,monitor);
    println(r!=null&&r.decompileCompleted()?r.getDecompiledFunction().getC():"<fail>");
  }
  public void run() throws Exception {
    sp=currentProgram.getAddressFactory().getDefaultAddressSpace();
    fm=currentProgram.getFunctionManager(); di=new DecompInterface(); di.openProgram(currentProgram);
    deco(0x0058afe4L, "Persistent::create (tag->class)");
  }
}
