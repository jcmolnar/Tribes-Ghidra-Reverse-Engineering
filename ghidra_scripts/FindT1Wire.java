// FindT1Wire — anchor T1Vista's wire-decode functions + factories via strings, to run the
// same crash hunt as 1.40. Finds "Invalid packet." (setLastError guard) + xref fns, and the
// Persistent::create pattern (bound 0x7ff/0x800 + indexed call) + createDataBlock.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.app.decompiler.*;
import java.io.*;
import java.util.*;

public class FindT1Wire extends GhidraScript {
  public void run() throws Exception {
    Listing lst=currentProgram.getListing();
    FunctionManager fm=currentProgram.getFunctionManager();
    ReferenceManager rm=currentProgram.getReferenceManager();
    DecompInterface di=new DecompInterface(); di.openProgram(currentProgram);
    PrintWriter pw=new PrintWriter(new BufferedWriter(new FileWriter(
      System.getProperty("user.home")+"/t1wire.txt")));

    // (A) net-error strings -> xref functions (the guarded wire unpacks / connection path)
    String[] want={"Invalid packet","packet version","upgrade your executable","Connection","ghost","DataBlock","datablock"};
    pw.println("===== (A) net/wire strings + xref functions =====");
    Set<Function> wireFns=new LinkedHashSet<>();
    DataIterator dit=lst.getDefinedData(true);
    while(dit.hasNext()){
      Data d=dit.next(); Object v=d.getValue(); if(!(v instanceof String)) continue; String s=(String)v;
      boolean m=false; for(String w:want) if(s.contains(w)){m=true;break;}
      if(!m||s.length()>60) continue;
      ReferenceIterator it=rm.getReferencesTo(d.getAddress()); List<String> xr=new ArrayList<>();
      while(it.hasNext()){ Reference r=it.next(); Function f=fm.getFunctionContaining(r.getFromAddress());
        if(f!=null){ wireFns.add(f); xr.add("0x"+Long.toHexString(r.getFromAddress().getOffset())+"("+f.getName()+")"); } }
      if(!xr.isEmpty()) pw.println("  \""+s+"\" @0x"+Long.toHexString(d.getAddress().getOffset())+"  <- "+xr);
    }

    // (B) Persistent::create candidates: a fn whose body bounds an index vs 0x7ff/0x800 then indexed-calls
    pw.println("\n===== (B) Persistent::create candidates (imm 0x7ff or 0x800 + indexed CALL) =====");
    int shown=0;
    for(Function f: fm.getFunctions(true)){
      if(f.getBody().getNumAddresses()>260) continue;  // create is small
      Address cur=f.getEntryPoint(); boolean bound=false, idxcall=false;
      for(int i=0;i<120;i++){ Instruction ins=lst.getInstructionAt(cur); if(ins==null) break; String s=ins.toString();
        if((s.startsWith("CMP")||s.startsWith("SUB")||s.startsWith("ADD"))&&(s.contains("0x7ff")||s.contains("0x800"))) bound=true;
        if(s.startsWith("CALL")&&s.contains("[")&&(s.contains("*0x4")||s.contains("EAX]")||s.contains("ECX]"))) idxcall=true;
        cur=cur.add(ins.getLength()); if(!f.getBody().contains(cur)) break;
      }
      if(bound&&idxcall&&shown<8){ pw.println("  candidate "+f.getName()+" @0x"+Long.toHexString(f.getEntryPoint().getOffset()));
        DecompileResults r=di.decompileFunction(f,40,monitor);
        if(r!=null&&r.decompileCompleted()){ String[] ls=r.getDecompiledFunction().getC().split("\n");
          for(int i=0;i<Math.min(ls.length,22);i++) pw.println("     "+ls[i]); }
        shown++;
      }
    }
    pw.close(); println("wrote re/t1wire.txt");
  }
}
