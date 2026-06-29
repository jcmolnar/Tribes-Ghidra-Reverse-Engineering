// Get T1Vista's ACTUAL registered tags for the event classes. The tag lives at classrep+0x90, set by the
// IMPLEMENT_PERSISTENT_TAG static-init constructor with an immediate. Find code refs to each event class-rep
// and decompile the constructor/static-init so we can read the tag immediate it stores at +0x90.
// Compare to our FearDcl.h (TeamObjective=1024, MissReset=1113, etc.).
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.mem.*;
import ghidra.app.decompiler.*;

public class RealTags extends GhidraScript {
  Memory mem; AddressSpace sp; FunctionManager fm; DecompInterface di; ReferenceManager rm;
  long u32(long va) throws MemoryAccessException { return mem.getInt(sp.getAddress(va)) & 0xffffffffL; }
  String nameAt(long va){
    try{ StringBuilder s=new StringBuilder(); Address a=sp.getAddress(va);
      for(int i=0;i<48;i++){int b=mem.getByte(a.add(i))&0xff; if(b==0)break;
        boolean ok=(b>='A'&&b<='Z')||(b>='a'&&b<='z')||(b>='0'&&b<='9')||b=='_'||b==':'; if(!ok)return null; s.append((char)b);}
      String r=s.toString(); return r.length()>=4?r:null;}catch(Exception e){return null;}
  }
  String realName(long vt){ try{ return nameAt(u32((vt-0x34)+0x1c)+0x30); }catch(Exception e){ return null; } }

  void probe(long classrep, String want) throws Exception {
    println("\n==== "+want+"  classrep=0x"+Long.toHexString(classrep)+" realName="+realName(classrep)+" ====");
    // refs to the class-rep address from code (the static init)
    boolean found=false;
    ReferenceIterator it=rm.getReferencesTo(sp.getAddress(classrep));
    java.util.LinkedHashSet<Function> fns=new java.util.LinkedHashSet<Function>();
    while(it.hasNext()){
      Reference r=it.next();
      Function f=fm.getFunctionContaining(r.getFromAddress());
      println("  ref from "+r.getFromAddress()+" in "+(f!=null?f.getName():"(data)"));
      if(f!=null) fns.add(f);
    }
    for(Function f: fns){
      println("  ---- static-init "+f.getName()+" ----");
      DecompileResults r=di.decompileFunction(f,60,monitor);
      if(r!=null&&r.decompileCompleted()){
        String c=r.getDecompiledFunction().getC();
        // print only lines mentioning the classrep or +0x90 or a 10xx/11xx immediate
        for(String line: c.split("\n"))
          if(line.contains("0x90")||line.contains("+ 0x90")||line.contains(Long.toHexString(classrep))||line.matches(".*\\b1[01][0-9][0-9]\\b.*"))
            println("      "+line.trim());
      }
      found=true;
    }
    if(!found) println("  (no code ref to class-rep)");
  }
  public void run() throws Exception {
    mem=currentProgram.getMemory(); sp=currentProgram.getAddressFactory().getDefaultAddressSpace();
    fm=currentProgram.getFunctionManager(); rm=currentProgram.getReferenceManager();
    di=new DecompInterface(); di.openProgram(currentProgram);
    probe(0x0060f9f4L, "TeamObjectiveEvent");
    probe(0x0060fb2cL, "MissResetEvent");
    probe(0x0063461cL, "SimConsoleEvent");
  }
}
