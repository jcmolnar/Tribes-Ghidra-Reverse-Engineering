// AIDel — find AIObj::removeThis + any path that deletes a bot, to determine whether the rep id is
// freed (onRemove->clientDropped) before/after the player is deleted. Dump all AIObj-module functions
// [0x43c000,0x440000]; flag ones that call SimObject::deleteObject (FUN_004fe858) and/or touch
// player(+0x1c0)/repId(+0x19c)/onRemove(FUN_43dbd8).
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.scalar.*;
import ghidra.program.model.symbol.*;
import ghidra.app.decompiler.*;
import java.io.*;
import java.util.*;

public class AIDel extends GhidraScript {
  PrintWriter pw; DecompInterface di; AddressSpace sp;
  String deco(Function f){
    DecompileResults r=di.decompileFunction(f,120,monitor);
    return (r!=null&&r.decompileCompleted())?r.getDecompiledFunction().getC():"<fail>";
  }
  boolean calls(Function f,long target){
    InstructionIterator it=currentProgram.getListing().getInstructions(f.getBody(),true);
    while(it.hasNext()){ Instruction ins=it.next();
      for(Reference r:ins.getReferencesFrom()) if(r.getReferenceType().isCall() && r.getToAddress().getOffset()==target) return true; }
    return false;
  }
  public void run() throws Exception {
    sp=currentProgram.getAddressFactory().getDefaultAddressSpace();
    di=new DecompInterface(); di.openProgram(currentProgram);
    pw=new PrintWriter(new BufferedWriter(new FileWriter("C:\\Users\\Joe\\Desktop\\Tribes Browser Based\\re\\aidel.txt")));

    long delObj=0x4fe858L;        // SimObject::deleteObject
    long onRemove=0x43dbd8L;      // AIObj::onRemove

    // (A) who CALLS AIObj::onRemove indirectly = who deletes the AIObj. onRemove is virtual (vtable),
    // so find direct deleteObject(aiObj) callers is hard; instead find removeThis = a fn that calls
    // delObj twice (player then self) and references +0x1c0.
    pw.println("===== AIObj-module functions [0x43c000,0x440000] =====");
    FunctionIterator fit=currentProgram.getFunctionManager().getFunctions(sp.getAddress(0x43c000L),true);
    List<Function> fns=new ArrayList<Function>();
    while(fit.hasNext()){ Function f=fit.next(); long a=f.getEntryPoint().getOffset(); if(a>=0x440000L)break; fns.add(f); }

    for(Function f: fns){
      // count delObj call sites + check refs to +0x1c0 / repId
      int delCalls=0; boolean ref1c0=false, ref19c=false, refClientDropped=false;
      InstructionIterator it=currentProgram.getListing().getInstructions(f.getBody(),true);
      while(it.hasNext()){ Instruction ins=it.next();
        for(Reference r:ins.getReferencesFrom()) if(r.getReferenceType().isCall()){
          long t=r.getToAddress().getOffset(); if(t==delObj) delCalls++; if(t==0x40c3d8L) refClientDropped=true; }
        for(int oi=0;oi<ins.getNumOperands();oi++) for(Object o:ins.getOpObjects(oi)) if(o instanceof Scalar){
          long v=((Scalar)o).getUnsignedValue(); if(v==0x1c0) ref1c0=true; if(v==0x19c) ref19c=true; }
      }
      if(delCalls>0 || refClientDropped || (ref1c0&&ref19c)){
        pw.println(String.format("\n##### FUN_%08x size=%d  delObjCalls=%d ref+0x1c0=%b ref+0x19c=%b clientDropped=%b #####",
          f.getEntryPoint().getOffset(), f.getBody().getNumAddresses(), delCalls, ref1c0, ref19c, refClientDropped));
        pw.println(deco(f));
      }
    }
    pw.close();
    println("wrote re/aidel.txt; scanned "+fns.size()+" fns");
  }
}
