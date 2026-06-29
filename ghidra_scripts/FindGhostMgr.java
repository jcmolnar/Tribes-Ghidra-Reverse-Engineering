// Find T1Vista's GhostManager::readPacket and the ghost unpackUpdate dispatch. Anchor: it calls
// Persistent::create (FUN_0058afe4) like EventManager, but the ghost path reads idSize=readInt(3)+3, a per-ghost
// readFlag loop, and tag=readInt(10) (NO +1024). So among create's callers, the ghost reader is the one that does
// NOT add 0x400 to the tag and has the readInt(3) idSize. Decompile all create callers to identify + dump it.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.app.decompiler.*;
import java.util.*;

public class FindGhostMgr extends GhidraScript {
  public void run() throws Exception {
    AddressSpace sp=currentProgram.getAddressFactory().getDefaultAddressSpace();
    FunctionManager fm=currentProgram.getFunctionManager();
    ReferenceManager rm=currentProgram.getReferenceManager();
    DecompInterface di=new DecompInterface(); di.openProgram(currentProgram);
    Address create=sp.getAddress(0x0058afe4L);
    Set<Function> callers=new LinkedHashSet<Function>();
    ReferenceIterator it=rm.getReferencesTo(create);
    while(it.hasNext()){ Function f=fm.getFunctionContaining(it.next().getFromAddress()); if(f!=null) callers.add(f); }
    println("Persistent::create callers: "+callers.size());
    for(Function f: callers){
      println("\n################ "+f.getName()+" @"+f.getEntryPoint()+" ################");
      DecompileResults r=di.decompileFunction(f,90,monitor);
      println(r!=null&&r.decompileCompleted()? r.getDecompiledFunction().getC() : "  <fail>");
    }
  }
}
