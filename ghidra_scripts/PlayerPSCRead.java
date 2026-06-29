// RE PlayerPSC::readPacket (the PacketStream child between EventManager and GhostManager). If our
// reconstruction mis-reads its SPAWNED (long control-object) form, it desyncs/swallows the GhostManager slice
// -> client reads zero ghosts even though spawned. Find the readPacket vtable SLOT via EventManager (vtbl
// 0x63f0b8 holds readPacket=0x551ef8), then read it from PlayerPSC's vtable (0x60f1b4) and GhostManager's, and
// decompile PlayerPSC::readPacket.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.app.decompiler.*;

public class PlayerPSCRead extends GhidraScript {
  Memory mem; AddressSpace sp; FunctionManager fm; DecompInterface di;
  long u32(long va) throws MemoryAccessException { return mem.getInt(sp.getAddress(va))&0xffffffffL; }
  String deco(long v){ Address pa=sp.getAddress(v); Function f=fm.getFunctionAt(pa); if(f==null)f=fm.getFunctionContaining(pa);
    if(f==null){try{disassemble(pa);f=createFunction(pa,null);}catch(Exception e){}}
    if(f==null)return "  <no func>"; DecompileResults r=di.decompileFunction(f,90,monitor);
    return (r!=null&&r.decompileCompleted())?r.getDecompiledFunction().getC():"  <fail>"; }
  public void run() throws Exception {
    mem=currentProgram.getMemory(); sp=currentProgram.getAddressFactory().getDefaultAddressSpace();
    fm=currentProgram.getFunctionManager(); di=new DecompInterface(); di.openProgram(currentProgram);
    long emVt=0x0063f0b8L, emRead=0x00551ef8L, ghostVt=0;
    // find readPacket slot in EventManager vtable
    int slot=-1;
    for(int off=0; off<0x120; off+=4){ if(u32(emVt+off)==emRead){ slot=off; break; } }
    println("readPacket vtable slot = 0x"+Integer.toHexString(slot));
    if(slot<0){ println("slot not found"); return; }
    long pscVt=0x0060f1b4L;       // PlayerPSC vtbl (from catalog)
    long pscRead=u32(pscVt+slot);
    long gmRead =u32(0x00552c94L+0); // we'll also confirm GhostManager
    println("PlayerPSC::readPacket = 0x"+Long.toHexString(pscRead));
    // confirm GhostManager readPacket via its vtable too: find a vtable whose slot == 0x552cc8
    println("(GhostManager::readPacket known = 0x552cc8)");
    println("\n################ PlayerPSC::readPacket @0x"+Long.toHexString(pscRead)+" ################");
    println(deco(pscRead));
  }
}
