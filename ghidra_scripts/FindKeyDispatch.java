// FindKeyDispatch — locate the keyboard->bind dispatch (the SimGame::processEvent
// equivalent) in a Tribes client binary, so Hudbot can detour it to add ScriptGL
// text input (swallow the key when text-input mode is on, instead of firing a bind).
//
// Run this on EACH deployment exe separately (open the program in the CodeBrowser,
// then Script Manager -> FindKeyDispatch):
//   - T1Vista.exe  (1.3, Borland)   -> re/keydispatch_T1Vista.exe.txt
//   - Tribes.exe   (1.40.655, MSVC) -> re/keydispatch_Tribes.exe.txt
//
// ANCHOR: the dispatch handles a KEYBOARD make and, before consulting the action
// map, special-cases the backtick `'`'` (ascii 0x60) to toggle the drop-down
// console (engine source: SimGame::processEvent
//   if(ev->deviceType==SI_KEYBOARD && ... ) {
//       if(ev->ascii=='`' && ev->action==SI_MAKE){ toggle console; return true; }
//       ...
//   }
//   n = gameActionMap->findMatch(ev);
//   if(n && n->action.consoleCommand) Console->evaluate(n->action.consoleCommand);
// ). A CMP/SUB against the immediate 0x60 on a key/ascii byte is the cleanest
// cross-compiler fingerprint of THIS function, so we scan for it and dump every
// containing function for inspection.
//
// HOW TO PICK THE WINNER from the dump: the target function is the one that
//   (a) takes one pointer arg (the event) and reads a small byte field for the
//       ascii (the 0x60 compare) plus other byte fields (deviceType/action),
//   (b) on the NON-backtick fall-through calls a lookup (action-map findMatch)
//       and then an evaluate with the looked-up string,
//   (c) returns a bool/int (handled vs not).
// Note its entry address + ABI (Borland T1Vista is typically __fastcall/stack;
// MSVC 1.40 SimGame::processEvent is __thiscall this=ECX, arg=event). Record both
// in re/keydispatch_<exe>.txt comments for the Hudbot per-exe address table.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.scalar.*;
import ghidra.app.decompiler.*;
import java.io.*;
import java.util.*;

public class FindKeyDispatch extends GhidraScript {
  DecompInterface di; FunctionManager fm; PrintWriter pw;
  Set<Long> done = new HashSet<Long>();

  // dump a function once, noting why it was flagged
  void deco(Function f, String why){
    if(f==null) return;
    long k=f.getEntryPoint().getOffset();
    if(!done.add(k)){
      pw.println("    (also: "+why+")");
      return;
    }
    pw.println("\n======== "+f.getName(true)+" @0x"+Long.toHexString(k)+"  ["+why+"] ========");
    DecompileResults r=di.decompileFunction(f,60,monitor);
    pw.println((r!=null && r.decompileCompleted())? r.getDecompiledFunction().getC() : "  <decompile failed>");
  }

  public void run() throws Exception {
    di=new DecompInterface(); di.openProgram(currentProgram);
    fm=currentProgram.getFunctionManager();

    String prog=currentProgram.getName();
    String out="C:\\Users\\Joe\\Desktop\\Tribes Browser Based\\re\\keydispatch_"+prog+".txt";
    pw=new PrintWriter(new BufferedWriter(new FileWriter(out)));
    pw.println("##### keyboard->bind dispatch candidates in "+prog+" #####");
    pw.println("# anchor: CMP/SUB against 0x60 ('`') - the console-toggle key above the action-map dispatch");
    pw.println("# imagebase=0x"+Long.toHexString(currentProgram.getImageBase().getOffset()));

    // collect (cmpAddr -> containing function) for every instruction that
    // compares a scalar operand to exactly 0x60
    List<long[]> hits=new ArrayList<long[]>();   // {cmpVA, funcEntryVA}
    Map<Long,String> fnHit=new LinkedHashMap<Long,String>();
    InstructionIterator ii=currentProgram.getListing().getInstructions(true);
    int scanned=0;
    while(ii.hasNext()){
      Instruction ins=ii.next(); scanned++;
      String m=ins.getMnemonicString();
      if(!(m.equals("CMP")||m.equals("SUB")||m.equals("XOR")||m.equals("TEST"))) continue;
      boolean is60=false;
      for(int op=0; op<ins.getNumOperands(); op++){
        Scalar s=ins.getScalar(op);
        if(s!=null && s.getUnsignedValue()==0x60L){ is60=true; break; }
      }
      if(!is60) continue;
      Function f=fm.getFunctionContaining(ins.getAddress());
      if(f==null) continue;
      long fe=f.getEntryPoint().getOffset();
      long ca=ins.getAddress().getOffset();
      hits.add(new long[]{ca,fe});
      if(!fnHit.containsKey(fe))
        fnHit.put(fe, "cmp ...,0x60 @0x"+Long.toHexString(ca));
    }

    pw.println("\n##### summary: "+fnHit.size()+" function(s) with a 0x60 compare (scanned "+scanned+" insns) #####");
    for(Map.Entry<Long,String> e: fnHit.entrySet()){
      Function f=fm.getFunctionAt(toAddr(e.getKey()));
      String nm=(f!=null)? f.getName(true) : "?";
      pw.println("  0x"+Long.toHexString(e.getKey())+"  "+nm+"   ("+e.getValue()+")");
    }

    // full decompile of each candidate (small set; eyeball for the key+actionmap shape)
    pw.println("\n##### decompiled candidates #####");
    for(Map.Entry<Long,String> e: fnHit.entrySet()){
      Function f=fm.getFunctionAt(toAddr(e.getKey()));
      deco(f, e.getValue());
    }

    pw.close();
    println("FindKeyDispatch: wrote "+out+"  ("+fnHit.size()+" candidate fns, "+hits.size()+" cmp-0x60 sites)");
  }
}
