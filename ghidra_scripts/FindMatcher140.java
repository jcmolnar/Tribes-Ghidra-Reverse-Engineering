// FindMatcher140 — in 1.40 Tribes.exe, find the wildcard string matcher (analog of T1Vista FUN_0058a87c):
// a recursive fn that compares bytes against 0x2a ('*') and 0x3f ('?'). Strategy: scan all functions for
// ones containing CMP ...,0x2a AND CMP ...,0x3f (the glob sentinels) and that recurse (self-call).
// Then for each, enumerate its callers and dump callers that have EXACTLY the twin shape:
//   small bool fn, 2 calls to matcher, structure [this+OBJ] deref + flag-gated 2nd call.
// Output: re/find_matcher140.txt
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.app.decompiler.*;
import java.io.*;
import java.util.*;

public class FindMatcher140 extends GhidraScript {
  DecompInterface di; FunctionManager fm; AddressSpace sp; Listing lst; ReferenceManager rm; PrintWriter pw;

  String dec(Function f){
    DecompileResults r=di.decompileFunction(f,120,monitor);
    return (r!=null&&r.decompileCompleted())? r.getDecompiledFunction().getC() : "  <decompile fail>";
  }

  public void run() throws Exception {
    di=new DecompInterface(); di.openProgram(currentProgram);
    fm=currentProgram.getFunctionManager(); sp=currentProgram.getAddressFactory().getDefaultAddressSpace();
    lst=currentProgram.getListing(); rm=currentProgram.getReferenceManager();
    pw=new PrintWriter(new BufferedWriter(new FileWriter(System.getProperty("user.home")+"/find_matcher140.txt")));

    // Pass 1: find candidate matchers — functions with CMP against 0x2a and 0x3f that self-recurse.
    List<Function> candidates=new ArrayList<Function>();
    FunctionIterator fi=fm.getFunctions(true);
    while(fi.hasNext()){
      Function f=fi.next();
      boolean has2a=false, has3f=false, recurse=false;
      Address a=f.getEntryPoint(); Address end=f.getBody().getMaxAddress(); int n=0;
      long ep=f.getEntryPoint().getOffset();
      while(a!=null && a.compareTo(end)<=0 && n<2000){
        Instruction ins=lst.getInstructionAt(a); if(ins==null){a=a.add(1);continue;}
        String op=ins.toString();
        if(op.startsWith("CMP")){
          if(op.contains("0x2a")) has2a=true;
          if(op.contains("0x3f")) has3f=true;
        }
        if(op.startsWith("CALL") && op.contains(Long.toHexString(ep))) recurse=true;
        a=ins.getAddress().add(ins.getLength()); n++;
      }
      if(has2a && has3f) candidates.add(f);
    }
    pw.println("=== matcher candidates (CMP 0x2a & 0x3f): "+candidates.size()+" ===");
    for(Function f: candidates){
      pw.println("  candidate 0x"+Long.toHexString(f.getEntryPoint().getOffset())+"  "+f.getName());
    }

    // For each candidate, decompile + dump callers' decompiles flagged by twin-shape heuristics.
    for(Function mfn: candidates){
      long mva=mfn.getEntryPoint().getOffset();
      pw.println("\n\n################################################################");
      pw.println("# MATCHER candidate 0x"+Long.toHexString(mva)+"  "+mfn.getName());
      pw.println("################################################################");
      pw.println(dec(mfn));

      Set<Long> callers=new TreeSet<Long>();
      ReferenceIterator ri=rm.getReferencesTo(mfn.getEntryPoint());
      while(ri.hasNext()){
        Reference ref=ri.next();
        Function cf=fm.getFunctionContaining(ref.getFromAddress());
        if(cf!=null && cf.getEntryPoint().getOffset()!=mva) callers.add(cf.getEntryPoint().getOffset());
      }
      pw.println("\n#### CALLERS of 0x"+Long.toHexString(mva)+": "+callers.size()+" ####");
      for(Long cva: callers){
        Function cf=fm.getFunctionAt(sp.getAddress(cva));
        if(cf==null) continue;
        // count calls to matcher
        int calls=0; Address a=cf.getEntryPoint(); Address end=cf.getBody().getMaxAddress();
        while(a!=null && a.compareTo(end)<=0){
          Instruction ins=lst.getInstructionAt(a); if(ins==null){a=a.add(1);continue;}
          String op=ins.toString();
          if(op.startsWith("CALL") && op.contains(Long.toHexString(mva))) calls++;
          a=ins.getAddress().add(ins.getLength());
        }
        // body size
        long size=cf.getBody().getNumAddresses();
        pw.println("\n==== caller 0x"+Long.toHexString(cva)+"  "+cf.getName()+"  callsToMatcher="+calls+"  size="+size+" ====");
        // only fully decompile the SMALL ones with exactly 2 matcher calls (the twin shape), to limit noise
        if(calls==2 && size<400){
          pw.println(dec(cf));
        } else {
          pw.println("   (skipped decompile — not twin shape: calls="+calls+" size="+size+")");
        }
      }
    }

    pw.close();
    println("wrote re/find_matcher140.txt  candidates="+candidates.size());
  }
}
