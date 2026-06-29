// DelVerify — settle deferred-vs-immediate deleteObject IN THE BINARY (T1Vista.exe), plus the
// client drop/cleanup path. Anchors via AssertFatal strings, then decompiles + disasms.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.*;
import ghidra.app.decompiler.*;
import java.io.*;
import java.util.*;

public class DelVerify extends GhidraScript {
  PrintWriter pw; DecompInterface di; AddressSpace sp; Memory mem;
  String deco(long va){
    Function f=getFunctionContaining(sp.getAddress(va));
    if(f==null){ try{disassemble(sp.getAddress(va)); f=createFunction(sp.getAddress(va),null);}catch(Exception e){} }
    if(f==null) return "  <no fn @0x"+Long.toHexString(va)+">";
    DecompileResults r=di.decompileFunction(f,120,monitor);
    return "FUN_"+Long.toHexString(f.getEntryPoint().getOffset())+":\n"+((r!=null&&r.decompileCompleted())?r.getDecompiledFunction().getC():"<fail>");
  }
  void disasm(long va){
    Function f=getFunctionContaining(sp.getAddress(va)); if(f==null) return;
    InstructionIterator it=currentProgram.getListing().getInstructions(f.getBody(),true);
    while(it.hasNext()){ Instruction ins=it.next(); StringBuilder b=new StringBuilder();
      try{for(byte x:ins.getBytes())b.append(String.format("%02x ",x&0xff));}catch(Exception e){}
      pw.println(String.format("    0x%08x  %-20s %s",ins.getAddress().getOffset(),b.toString().trim(),ins.toString())); }
  }
  List<Long> findStr(String s){
    List<Long> h=new ArrayList<Long>(); byte[] pat=s.getBytes();
    for(MemoryBlock b:mem.getBlocks()){ if(!b.isInitialized())continue;
      try{ byte[] buf=new byte[(int)b.getSize()]; mem.getBytes(b.getStart(),buf);
        for(int i=0;i+pat.length<buf.length;i++){boolean ok=true;
          for(int j=0;j<pat.length;j++) if(buf[i+j]!=pat[j]){ok=false;break;}
          if(ok) h.add(b.getStart().getOffset()+i);}
      }catch(Exception e){} }
    return h;
  }
  // find functions whose body PUSHes/LEAs the address 'a' (xref via reference manager + byte scan)
  Set<Long> refFns(long a){
    Set<Long> s=new LinkedHashSet<Long>();
    ReferenceIterator it=currentProgram.getReferenceManager().getReferencesTo(sp.getAddress(a));
    while(it.hasNext()){ Reference r=it.next(); Function f=getFunctionContaining(r.getFromAddress()); if(f!=null) s.add(f.getEntryPoint().getOffset()); }
    // byte scan fallback
    MemoryBlock tb=mem.getBlock(".text");
    try{ byte[] buf=new byte[(int)tb.getSize()]; mem.getBytes(tb.getStart(),buf); long base=tb.getStart().getOffset();
      byte b0=(byte)(a&0xff),b1=(byte)((a>>8)&0xff),b2=(byte)((a>>16)&0xff),b3=(byte)((a>>24)&0xff);
      for(int i=0;i+3<buf.length;i++) if(buf[i]==b0&&buf[i+1]==b1&&buf[i+2]==b2&&buf[i+3]==b3){
        Function f=getFunctionContaining(sp.getAddress(base+i)); if(f!=null) s.add(f.getEntryPoint().getOffset()); }
    }catch(Exception e){}
    return s;
  }
  void dumpFor(String label, String str){
    pw.println("\n======== "+label+"  (anchor str \""+str+"\") ========");
    for(long h: findStr(str)){
      Set<Long> fns=refFns(h);
      pw.println("  str@0x"+Long.toHexString(h)+" -> fns "+fns);
      for(long fn: fns){ pw.println(deco(fn)); pw.println("  ---- disasm ----"); disasm(fn); }
    }
  }
  public void run() throws Exception {
    sp=currentProgram.getAddressFactory().getDefaultAddressSpace(); mem=currentProgram.getMemory();
    di=new DecompInterface(); di.openProgram(currentProgram);
    pw=new PrintWriter(new BufferedWriter(new FileWriter("C:\\Users\\Joe\\Desktop\\Tribes Browser Based\\re\\delverify.txt")));

    // 1. SimManager::deleteObject — THE contested point (deferred deleteList vs immediate delete)
    dumpFor("SimManager::deleteObject", "already been deleted");
    dumpFor("SimManager::deleteObject (alt)", "process of being removed");
    // 2. SimObject::deleteObject
    dumpFor("SimObject::deleteObject", "not registered with manager");
    // 3. client drop path
    dumpFor("clientDropped", "dropped - id");
    pw.close();
    println("wrote re/delverify.txt");
  }
}
