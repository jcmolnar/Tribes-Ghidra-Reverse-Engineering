// Find TeamObjectiveEvent's persistent/wire tag. The registration code references the class vtable
// (0x0060f9c0) and/or descriptor (0x0040e0e4) together with the tag constant (in 1024..1151 = 0x400..0x47f).
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.app.decompiler.*;

public class FindTag extends GhidraScript {
  AddressSpace sp; DecompInterface di; FunctionManager fm;
  void decoFn(Function f, String tag){
    if(f==null){println("  <no func "+tag+">");return;}
    println("\n######## "+tag+"  "+f.getName()+" @"+f.getEntryPoint()+" ########");
    DecompileResults r=di.decompileFunction(f,50,monitor);
    println(r!=null&&r.decompileCompleted()?r.getDecompiledFunction().getC():"  <fail>");
  }
  void refsTo(long target){
    Address a=sp.getAddress(target);
    ReferenceManager rm=currentProgram.getReferenceManager();
    println("=== refs to 0x"+Long.toHexString(target)+" ===");
    ReferenceIterator it=rm.getReferencesTo(a);
    java.util.LinkedHashSet<Function> fns=new java.util.LinkedHashSet<Function>();
    while(it.hasNext()){ Reference r=it.next(); Address frm=r.getFromAddress();
      Function f=fm.getFunctionContaining(frm);
      println("  from "+frm+" in "+(f!=null?f.getName():"(data)")+" type="+r.getReferenceType());
      if(f!=null) fns.add(f);
    }
    int n=0; for(Function f: fns){ decoFn(f,"ref-fn"); if(++n>=3)break; }
  }
  public void run() throws Exception {
    sp=currentProgram.getAddressFactory().getDefaultAddressSpace();
    fm=currentProgram.getFunctionManager(); di=new DecompInterface(); di.openProgram(currentProgram);
    refsTo(0x0060f9c0L);   // vtable
    refsTo(0x0040e0e4L);   // descriptor (holds name)
    // also: the create function for the class is often near the vtable use; and the pack fn 0x40a5a8
    // is only called from the persistent machinery — show its callers too.
    refsTo(0x0040a5a8L);
  }
}
