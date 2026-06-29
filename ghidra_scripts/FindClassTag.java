// Find EventManager::readPacket in T1Vista and read the EXACT classTag width. Our source reads
// readInt(7)+1024; if the real binary differs, that's the per-event offset desyncing the objective burst.
// Anchor: readPacket reads the classTag then does `+ 0x400` (1024) and calls Persistent::create. So find
// functions that (a) call BS_readInt (FUN_00582f70) AND (b) reference the scalar 0x400, and decompile them.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.scalar.Scalar;
import ghidra.app.decompiler.*;
import java.util.*;

public class FindClassTag extends GhidraScript {
  public void run() throws Exception {
    AddressSpace sp=currentProgram.getAddressFactory().getDefaultAddressSpace();
    FunctionManager fm=currentProgram.getFunctionManager();
    ReferenceManager rm=currentProgram.getReferenceManager();
    Listing lst=currentProgram.getListing();
    DecompInterface di=new DecompInterface(); di.openProgram(currentProgram);

    // 1) collect functions that call BS_readInt (FUN_00582f70 @0x582f70)
    Address readInt=sp.getAddress(0x00582f70L);
    Set<Function> callers=new LinkedHashSet<Function>();
    ReferenceIterator it=rm.getReferencesTo(readInt);
    while(it.hasNext()){
      Reference r=it.next();
      Function f=fm.getFunctionContaining(r.getFromAddress());
      if(f!=null) callers.add(f);
    }
    println("BS_readInt callers: "+callers.size());

    // 2) of those, keep functions whose body references the scalar 0x400 (1024 = classTag base)
    List<Function> hits=new ArrayList<Function>();
    for(Function f: callers){
      boolean has400=false;
      InstructionIterator ii=lst.getInstructions(f.getBody(), true);
      while(ii.hasNext() && !has400){
        Instruction in=ii.next();
        for(int op=0; op<in.getNumOperands() && !has400; op++){
          for(Object o: in.getOpObjects(op)){
            if(o instanceof Scalar && ((Scalar)o).getUnsignedValue()==0x400L){ has400=true; break; }
          }
        }
      }
      if(has400) hits.add(f);
    }
    println("callers that also reference 0x400 (classTag base): "+hits.size());
    for(Function f: hits) println("  candidate readPacket: "+f.getName()+" @"+f.getEntryPoint());

    // 3) decompile each candidate so we can read the classTag width + per-event framing
    for(Function f: hits){
      println("\n################ "+f.getName()+" @"+f.getEntryPoint()+" ################");
      DecompileResults r=di.decompileFunction(f,90,monitor);
      println(r!=null&&r.decompileCompleted()? r.getDecompiledFunction().getC() : "  <fail>");
    }
  }
}
