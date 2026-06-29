// Recover T1Vista's ACTUAL tag->class registrations. fastTable @0x6bed90 is written by the persistent
// registration (IMPLEMENT_PERSISTENT_TAG static init). Find code that references the fastTable region and
// decompile it -> the (tag, classrep) pairs. Compare to our FearDcl.h.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.app.decompiler.*;
import java.util.*;

public class FindReg extends GhidraScript {
  public void run() throws Exception {
    AddressSpace sp=currentProgram.getAddressFactory().getDefaultAddressSpace();
    FunctionManager fm=currentProgram.getFunctionManager();
    ReferenceManager rm=currentProgram.getReferenceManager();
    DecompInterface di=new DecompInterface(); di.openProgram(currentProgram);

    // references to anywhere in the fastTable array [0x6bed90 .. 0x6bed90 + 2048*4)
    long base=0x006bed90L, end=base + 2048L*4;
    Set<Function> writers=new LinkedHashSet<Function>();
    int refCount=0;
    for(long a=base; a<end; a+=4){
      ReferenceIterator it=rm.getReferencesTo(sp.getAddress(a));
      while(it.hasNext()){
        Reference r=it.next(); refCount++;
        Function f=fm.getFunctionContaining(r.getFromAddress());
        if(f!=null) writers.add(f);
      }
    }
    println("refs into fastTable: "+refCount+"  distinct functions: "+writers.size());
    int n=0;
    for(Function f: writers){
      println("\n################ "+f.getName()+" @"+f.getEntryPoint()+" ################");
      DecompileResults r=di.decompileFunction(f,90,monitor);
      println(r!=null&&r.decompileCompleted()? r.getDecompiledFunction().getC() : "  <fail>");
      if(++n>=6){ println("\n... ("+(writers.size()-6)+" more writers omitted)"); break; }
    }
  }
}
