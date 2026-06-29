// AIFix140 — full disassembly of the 1.40 AI-crash analog FUN_004298c0 (twin of T1Vista FUN_0043ffbc),
// to pin the exact crash instruction (MOV reg,[objptr+0x250]), the register holding *(this+0x1cc), the
// flag-gate JZ skip target, and confirm there's no existing NULL guard on *(this+0x1cc). Also resolves
// the RTTI class identity of FUN_004298c0 (which vtable slot it sits in) so we can name it.
// Output: re/aifix140.txt
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.mem.*;
import ghidra.app.decompiler.*;
import java.io.*;
import java.util.*;

public class AIFix140 extends GhidraScript {
  DecompInterface di; FunctionManager fm; AddressSpace sp; Listing lst; Memory mem; SymbolTable st; PrintWriter pw;
  long textMin, textMax;
  long u32(long va) throws Exception { return mem.getInt(sp.getAddress(va)) & 0xffffffffL; }
  boolean inText(long v){ return v>=textMin && v<textMax; }
  String fnName(long fa){
    Address a=sp.getAddress(fa);
    Function f=fm.getFunctionAt(a); if(f!=null) return f.getName(true);
    Symbol s=st.getPrimarySymbol(a); return s!=null? s.getName(true):"";
  }

  public void run() throws Exception {
    di=new DecompInterface(); di.openProgram(currentProgram);
    fm=currentProgram.getFunctionManager(); sp=currentProgram.getAddressFactory().getDefaultAddressSpace();
    lst=currentProgram.getListing(); mem=currentProgram.getMemory(); st=currentProgram.getSymbolTable();
    MemoryBlock tb=mem.getBlock(".text"); textMin=tb.getStart().getOffset(); textMax=tb.getEnd().getOffset();
    pw=new PrintWriter(new BufferedWriter(new FileWriter("C:\\Users\\Joe\\Desktop\\Tribes Browser Based\\re\\aifix140.txt")));

    long fnVA=0x4298c0L;
    Function f=fm.getFunctionAt(sp.getAddress(fnVA));
    pw.println("############ 1.40 AI crash analog FUN_004298c0 @0x"+Long.toHexString(fnVA)+" ############");
    pw.println("name="+(f!=null?f.getName():"<none>"));

    pw.println("\n---- full disassembly ----");
    Address a=f.getEntryPoint(); Address end=f.getBody().getMaxAddress();
    while(a!=null && a.compareTo(end)<=0){
      Instruction ins=lst.getInstructionAt(a); if(ins==null){a=a.add(1);continue;}
      String op=ins.toString();
      String mark="";
      if(op.contains("0x250")) mark="   <<<< BOX deref (+0x250) — CRASH SITE candidate";
      if(op.contains("0x1cc")) mark="   <<<< OBJ ptr load (+0x1cc)";
      if(op.contains("0x54") && op.startsWith("TEST")) mark="   <<<< FLAGS (+0x54) test";
      if(op.startsWith("AND") && op.contains("0x54")) mark="   <<<< FLAGS (+0x54) and";
      if(op.startsWith("JZ")||op.startsWith("JNZ")) mark+="   ; branch";
      if(op.contains("00411bb0")) mark+="   ; CALL matcher";
      pw.println(String.format("  0x%08x  %-40s%s", a.getOffset(), op, mark));
      a=ins.getAddress().add(ins.getLength());
    }

    pw.println("\n---- decompile ----");
    DecompileResults r=di.decompileFunction(f,90,monitor);
    pw.println((r!=null&&r.decompileCompleted())? r.getDecompiledFunction().getC():"  <fail>");

    // RTTI: which vtable holds 0x4298c0? scan vftable symbols' slots
    pw.println("\n---- RTTI: vtables referencing 0x4298c0 ----");
    SymbolIterator it=st.getAllSymbols(true);
    while(it.hasNext()){
      Symbol s=it.next();
      String n=s.getName(true);
      if(!n.contains("vftable")) continue;
      long vt=s.getAddress().getOffset();
      for(int i=0;i<80;i++){
        long slot; try{ slot=u32(vt+i*4L);}catch(Exception ex){break;}
        if(!inText(slot)){ if(i>4) break; else continue; }
        if(slot==fnVA){ pw.println("   "+n+" @0x"+Long.toHexString(vt)+"  slot["+i+"] (+0x"+Integer.toHexString(i*4)+")"); }
      }
    }

    // Also dump the matcher fn name and the callers of FUN_004298c0 to identify the AI/scope call path.
    pw.println("\n---- callers of FUN_004298c0 (the scope-query entry) ----");
    ReferenceManager rm=currentProgram.getReferenceManager();
    ReferenceIterator ri=rm.getReferencesTo(f.getEntryPoint());
    Set<Long> seen=new TreeSet<Long>();
    while(ri.hasNext()){
      Reference ref=ri.next();
      Function cf=fm.getFunctionContaining(ref.getFromAddress());
      String fromCtx = cf!=null? (cf.getName()+" @0x"+Long.toHexString(cf.getEntryPoint().getOffset())) : "<none>";
      pw.println("   ref from 0x"+Long.toHexString(ref.getFromAddress().getOffset())+"  type="+ref.getReferenceType()+"  in "+fromCtx);
    }
    // Is 0x4298c0 itself in a vtable? Already covered. Print matcher identity.
    pw.println("\n   matcher FUN_00411bb0 name="+fnName(0x411bb0L));

    pw.close();
    println("wrote re/aifix140.txt");
  }
}
