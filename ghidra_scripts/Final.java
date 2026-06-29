// Final — settle: (1) does clean()/setGenericDefaults clear rep+0x98 (ownedObject) / control on reuse;
// (2) is SimManager::deleteObject FUN_004ffa4c immediate or deferred (the disputed point).
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.app.decompiler.*;
import java.io.*;

public class Final extends GhidraScript {
  PrintWriter pw; DecompInterface di; AddressSpace sp;
  void dump(long va,String tag){
    Function f=getFunctionContaining(sp.getAddress(va));
    if(f==null){ try{disassemble(sp.getAddress(va)); f=createFunction(sp.getAddress(va),null);}catch(Exception e){} }
    pw.println("\n##### "+tag+"  FUN_"+Long.toHexString(va)+" #####");
    if(f==null){ pw.println("<no fn>"); return; }
    DecompileResults r=di.decompileFunction(f,120,monitor);
    pw.println((r!=null&&r.decompileCompleted())?r.getDecompiledFunction().getC():"<fail>");
    pw.println("  ---- disasm ----");
    InstructionIterator it=currentProgram.getListing().getInstructions(f.getBody(),true);
    while(it.hasNext()){ Instruction ins=it.next(); StringBuilder b=new StringBuilder();
      try{for(byte x:ins.getBytes())b.append(String.format("%02x ",x&0xff));}catch(Exception e){}
      pw.println(String.format("    0x%08x  %-20s %s",ins.getAddress().getOffset(),b.toString().trim(),ins.toString())); }
  }
  public void run() throws Exception {
    sp=currentProgram.getAddressFactory().getDefaultAddressSpace();
    di=new DecompInterface(); di.openProgram(currentProgram);
    pw=new PrintWriter(new BufferedWriter(new FileWriter("C:\\Users\\Joe\\Desktop\\Tribes Browser Based\\re\\final.txt")));
    dump(0x40b754L,"clean()");
    dump(0x40b168L,"setGenericDefaults()");
    dump(0x4fe858L,"SimObject::deleteObject (wrapper)");
    dump(0x4ffa4cL,"SimManager::deleteObject (deferred vs immediate)");
    pw.close();
    println("wrote re/final.txt");
  }
}
