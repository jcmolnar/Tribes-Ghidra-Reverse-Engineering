// FindConsoleAbi — locate the CMDConsole seam in T1Vista.exe (1.3, Borland) so
// Hudbot can be ported to it: addCommand (register gl* commands), executef /
// evaluate (call ScriptGL::onChar etc.), and the Console global.
//
// Anchors:
//   - Console global = DAT_006583c4 (found via the keydispatch RE: it calls
//     evaluate(DAT_006583c4, cmd) at 0x50d6.. -> FUN_005f41a8).
//   - addCommand: find a known stock console-command NAME string ("trace",
//     "exec", "echo", "quit", "metrics", "cls", "export", "help", "dumpConsoleFunctions"),
//     take its code xref, and decompile the containing registrar - the function it
//     calls once per command (with name+codeptr) IS addCommand. We tally the most
//     common callee across all registrar sites to surface it.
// Output: re/console_abi_T1Vista.exe.txt
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.scalar.*;
import ghidra.app.decompiler.*;
import java.io.*;
import java.util.*;

public class FindConsoleAbi extends GhidraScript {
  DecompInterface di; FunctionManager fm; PrintWriter pw; ReferenceManager rm;
  Set<Long> done=new HashSet<Long>();
  void deco(Function f,String why){
    if(f==null) return; long k=f.getEntryPoint().getOffset(); if(!done.add(k)) return;
    pw.println("\n======== "+f.getName(true)+" @0x"+Long.toHexString(k)+"  ["+why+"] ========");
    pw.println("  conv="+f.getCallingConventionName()+"  sig="+f.getSignature().getPrototypeString());
    DecompileResults r=di.decompileFunction(f,60,monitor);
    pw.println((r!=null&&r.decompileCompleted())? r.getDecompiledFunction().getC():"  <fail>");
  }
  public void run() throws Exception {
    if(!currentProgram.getName().equalsIgnoreCase("T1Vista.exe")){ println("run on T1Vista.exe"); return; }
    di=new DecompInterface(); di.openProgram(currentProgram);
    fm=currentProgram.getFunctionManager(); rm=currentProgram.getReferenceManager();
    pw=new PrintWriter(new BufferedWriter(new FileWriter(
      System.getProperty("user.home")+"/console_abi_T1Vista.exe.txt")));

    long consoleGlobal=0x006583c4L;
    pw.println("##### CMDConsole ABI — T1Vista.exe #####");
    pw.println("Console global (from keydispatch RE): DAT_0x"+Long.toHexString(consoleGlobal));
    pw.println("evaluate (from keydispatch RE):        FUN_005f41a8");

    // count xrefs to the console global (sanity)
    int cg=0; ReferenceIterator cri=rm.getReferencesTo(toAddr(consoleGlobal));
    while(cri.hasNext()){ cri.next(); cg++; }
    pw.println("xrefs to console global: "+cg);

    // 1) find command-name strings -> registrar functions -> tally the callee (=addCommand)
    String[] names={"trace","exec","echo","quit","metrics","cls","export","help",
                    "dumpConsoleFunctions","removeTaggedString","activatePackage","deactivatePackage"};
    Map<Long,Integer> calleeTally=new HashMap<Long,Integer>();
    Set<Long> registrars=new LinkedHashSet<Long>();
    Listing lst=currentProgram.getListing();
    DataIterator dit=lst.getDefinedData(true);
    int strHits=0;
    while(dit.hasNext()){
      Data d=dit.next();
      Object v=d.getValue();
      if(!(v instanceof String)) continue;
      String s=(String)v;
      boolean match=false;
      for(String nm:names) if(s.equals(nm)){ match=true; break; }
      if(!match) continue;
      ReferenceIterator ri=rm.getReferencesTo(d.getAddress());
      while(ri.hasNext()){
        Reference r=ri.next();
        Function f=fm.getFunctionContaining(r.getFromAddress());
        if(f==null) continue;
        strHits++;
        registrars.add(f.getEntryPoint().getOffset());
      }
    }
    pw.println("command-name string xref sites in "+registrars.size()+" registrar fn(s) (strHits="+strHits+")");

    // tally CALL targets inside each registrar (the most common = addCommand)
    for(Long re: registrars){
      Function f=fm.getFunctionAt(toAddr(re)); if(f==null) continue;
      InstructionIterator ii=lst.getInstructions(f.getBody(),true);
      while(ii.hasNext()){
        Instruction ins=ii.next();
        if(!ins.getFlowType().isCall()) continue;
        Reference[] rs=ins.getReferencesFrom();
        for(Reference r:rs){
          if(r.getReferenceType().isCall()){
            long t=r.getToAddress().getOffset();
            Integer c=calleeTally.get(t); calleeTally.put(t, c==null?1:c+1);
          }
        }
      }
    }
    // sort tally desc
    List<Map.Entry<Long,Integer>> es=new ArrayList<Map.Entry<Long,Integer>>(calleeTally.entrySet());
    es.sort(new Comparator<Map.Entry<Long,Integer>>(){
      public int compare(Map.Entry<Long,Integer> a,Map.Entry<Long,Integer> b){ return b.getValue()-a.getValue(); }});
    pw.println("\n##### most-called functions inside the registrars (top = likely addCommand) #####");
    int shown=0;
    for(Map.Entry<Long,Integer> e:es){
      Function f=fm.getFunctionAt(toAddr(e.getKey()));
      pw.println("  x"+e.getValue()+"  0x"+Long.toHexString(e.getKey())+"  "+(f!=null?f.getName():"?")
                 +(f!=null?"  conv="+f.getCallingConventionName():""));
      if(++shown>=12) break;
    }

    // 2) decompile the top callee (addCommand) + the evaluate neighborhood (executef lives near it)
    if(!es.isEmpty()) deco(fm.getFunctionAt(toAddr(es.get(0).getKey())), "TOP callee in registrars = likely addCommand");
    deco(fm.getFunctionAt(toAddr(0x005f41a8L)), "evaluate (from keydispatch)");
    // executef is usually adjacent in the CMDConsole method cluster; decompile a window of neighbors
    for(long a=0x005f3e00L; a<=0x005f4400L; ){
      Function f=fm.getFunctionContaining(toAddr(a));
      if(f!=null){ deco(f,"CMDConsole cluster neighbor"); a=f.getBody().getMaxAddress().getOffset()+1; }
      else a+=4;
    }

    // 3) one registrar decompiled in full (shows the addCommand call shape / args)
    if(!registrars.isEmpty())
      deco(fm.getFunctionAt(toAddr(registrars.iterator().next())), "a command registrar (addCommand call shape)");

    pw.close();
    println("FindConsoleAbi: wrote re/console_abi_T1Vista.exe.txt (registrars="+registrars.size()+", callees="+calleeTally.size()+")");
  }
}
