// BmpLoad — locate T1Vista's GFXBitmap reader/loader (strings stripped, so anchor structurally on
// the image magic constants the reader compares: 0x474e5089 PNG, 0x4d42 'BM', 0x504d4250 'PBMP'-ish).
// Find functions containing those scalars (= GFXBitmap::Read), then their callers (= ::load(stream)
// and ResourceManager bmp factory) and decompile, so we can see how a bitmap name flows to a GFXBitmap*.
// Output: re/bmpload.txt
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.scalar.*;
import ghidra.program.model.symbol.*;
import ghidra.app.decompiler.*;
import java.io.*;
import java.util.*;

public class BmpLoad extends GhidraScript {
  PrintWriter pw; DecompInterface di; AddressSpace sp; FunctionManager fm;
  String decomp(long va){
    Function f=fm.getFunctionContaining(sp.getAddress(va));
    if(f==null){ try{disassemble(sp.getAddress(va)); f=createFunction(sp.getAddress(va),null);}catch(Exception e){} }
    if(f==null) return "  <no fn @0x"+Long.toHexString(va)+">";
    DecompileResults r=di.decompileFunction(f,90,monitor);
    return "FUN_"+Long.toHexString(f.getEntryPoint().getOffset())+" (size "+f.getBody().getNumAddresses()+"):\n"
      +((r!=null&&r.decompileCompleted())?r.getDecompiledFunction().getC():"<decompile fail>");
  }
  Set<Long> fnsWithScalar(long val){
    Set<Long> s=new LinkedHashSet<Long>();
    InstructionIterator it=currentProgram.getListing().getInstructions(true);
    while(it.hasNext()){ Instruction ins=it.next();
      for(int oi=0;oi<ins.getNumOperands();oi++) for(Object o:ins.getOpObjects(oi))
        if(o instanceof Scalar && ((Scalar)o).getUnsignedValue()==val){
          Function f=fm.getFunctionContaining(ins.getAddress()); if(f!=null) s.add(f.getEntryPoint().getOffset()); }
    }
    return s;
  }
  Set<Long> callersOf(long va){
    Set<Long> s=new LinkedHashSet<Long>();
    ReferenceIterator it=currentProgram.getReferenceManager().getReferencesTo(sp.getAddress(va));
    while(it.hasNext()){ Reference r=it.next(); if(!r.getReferenceType().isCall()) continue;
      Function f=fm.getFunctionContaining(r.getFromAddress()); if(f!=null) s.add(f.getEntryPoint().getOffset()); }
    return s;
  }
  public void run() throws Exception {
    sp=currentProgram.getAddressFactory().getDefaultAddressSpace();
    fm=currentProgram.getFunctionManager();
    di=new DecompInterface(); di.openProgram(currentProgram);
    pw=new PrintWriter(new BufferedWriter(new FileWriter(System.getProperty("user.home")+"/bmpload.txt")));

    long[] magics={0x474e5089L, 0x504d4250L, 0x4d42L, 0x504d4258L};
    Set<Long> readers=new LinkedHashSet<Long>();
    for(long m:magics){
      Set<Long> fns=fnsWithScalar(m);
      pw.println("magic 0x"+Long.toHexString(m)+" in fns: "+fns);
      readers.addAll(fns);
    }
    pw.println("\n############ candidate GFXBitmap::Read fns ############");
    Set<Long> callers=new LinkedHashSet<Long>();
    for(long fn:readers){
      pw.println("\n################ READER FUN_"+Long.toHexString(fn)+" ################");
      pw.println(decomp(fn));
      Set<Long> c=callersOf(fn);
      pw.println("  callers: "+c);
      callers.addAll(c);
    }
    pw.println("\n############ callers (load / resource factory) ############");
    Set<Long> grand=new LinkedHashSet<Long>();
    for(long fn:callers){
      if(readers.contains(fn)) continue;
      pw.println("\n################ CALLER FUN_"+Long.toHexString(fn)+" ################");
      pw.println(decomp(fn));
      grand.addAll(callersOf(fn));
    }
    pw.println("\n############ grand-callers (who passes a name) ############");
    pw.println("grandcallers: "+grand);
    pw.close();
    println("wrote re/bmpload.txt; readers="+readers+" callers="+callers);
  }
}
