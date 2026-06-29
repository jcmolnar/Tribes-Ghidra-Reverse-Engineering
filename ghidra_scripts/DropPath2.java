// DropPath2 — decompile the PlayerManager cluster (neighbors of clientAdded FUN_0040b788) to find
// clientDropped + removeClient in the BINARY (functions touching the client lists +0x340f0/+0x340ec/+0x340f4),
// and locate SimManager::deleteObject (flag-set + 2x dict-remove + unregister + operator delete vs deleteList push).
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.scalar.*;
import ghidra.app.decompiler.*;
import java.io.*;
import java.util.*;

public class DropPath2 extends GhidraScript {
  PrintWriter pw; DecompInterface di; AddressSpace sp;
  String deco(Function f){
    DecompileResults r=di.decompileFunction(f,120,monitor);
    return "FUN_"+Long.toHexString(f.getEntryPoint().getOffset())+" (size "+f.getBody().getNumAddresses()+"):\n"
      +((r!=null&&r.decompileCompleted())?r.getDecompiledFunction().getC():"<fail>");
  }
  boolean refsAny(Function f, long[] offs){
    InstructionIterator it=currentProgram.getListing().getInstructions(f.getBody(),true);
    while(it.hasNext()){ Instruction ins=it.next();
      for(int oi=0;oi<ins.getNumOperands();oi++) for(Object o:ins.getOpObjects(oi))
        if(o instanceof Scalar){ long v=((Scalar)o).getUnsignedValue(); for(long t:offs) if(v==t) return true; }
    }
    return false;
  }
  public void run() throws Exception {
    sp=currentProgram.getAddressFactory().getDefaultAddressSpace();
    di=new DecompInterface(); di.openProgram(currentProgram);
    pw=new PrintWriter(new BufferedWriter(new FileWriter(System.getProperty("user.home")+"/droppath2.txt")));

    long[] listOffs={0x340f0L,0x340ecL,0x340f4L};
    pw.println("===== PlayerManager-cluster functions [0x40b788,0x40c800] that touch the client lists =====");
    FunctionIterator fit=currentProgram.getFunctionManager().getFunctions(sp.getAddress(0x40b788L),true);
    while(fit.hasNext()){
      Function f=fit.next(); long a=f.getEntryPoint().getOffset(); if(a>=0x40c800L)break;
      if(a==0x40b788L) continue; // clientAdded, already have it
      if(refsAny(f,listOffs)){
        pw.println("\n----------------------------------------------------------------");
        pw.println(deco(f));
      }
    }

    // SimManager::deleteObject: scan .text for a function that does operator-delete on its arg after
    // removing from dictionaries; heuristic — find small functions calling a free-like fn. Instead,
    // dump the decompile of the function reachable as SimObject::deleteObject wrapper if we can find a
    // 1-line "manager->deleteObject(this)" thunk. Fallback: list candidates referencing a "deleteList".
    pw.println("\n\n===== candidate SimManager::deleteObject (manager->deleteObject) =====");
    // SimObject::deleteObject is tiny: loads manager (this+off), virtual-calls deleteObject. We can't
    // resolve the vtable statically here; instead leave a marker for manual follow from clientDropped's disasm.
    pw.println("(resolve from clientDropped's ownedObject->deleteObject call target in droppath2 decompiles above)");
    pw.close();
    println("wrote re/droppath2.txt");
  }
}
