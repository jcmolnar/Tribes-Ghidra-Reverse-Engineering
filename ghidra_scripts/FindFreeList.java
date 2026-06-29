// FindFreeList — find every instruction that touches the client free-list region
// (SimManager + ~0x24E2C) so we can learn its structure + the engine's add/remove logic,
// then expose them to script. Reports referencing functions + decompiles the small ones.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.scalar.Scalar;
import ghidra.app.decompiler.*;
import java.io.*;
import java.util.*;

public class FindFreeList extends GhidraScript {
  public void run() throws Exception {
    Listing lst=currentProgram.getListing();
    DecompInterface di=new DecompInterface(); di.openProgram(currentProgram);
    PrintWriter pw=new PrintWriter(new BufferedWriter(new FileWriter(
      "C:\\Users\\Joe\\Desktop\\Tribes Browser Based\\re\\freelist.txt")));
    long lo=0x340e0, hi=0x34100;   // client lists: +0x340ec active, +0x340f0 free pool, +0x340f4 secondary
    Map<Function,List<String>> hits=new LinkedHashMap<>();
    InstructionIterator it=lst.getInstructions(true);
    while(it.hasNext()){
      Instruction ins=it.next();
      for(int op=0; op<ins.getNumOperands(); op++){
        for(Object o: ins.getOpObjects(op)){
          if(o instanceof Scalar){ long v=((Scalar)o).getUnsignedValue();
            if(v>=lo && v<hi){
              Function f=currentProgram.getFunctionManager().getFunctionContaining(ins.getAddress());
              hits.computeIfAbsent(f,k->new ArrayList<>()).add(String.format("0x%08x  %s  (off 0x%x)",ins.getAddress().getOffset(),ins.toString(),v));
            }
          }
        }
      }
    }
    pw.println("===== functions touching the free-list region (offset ~0x24E2C) =====");
    for(Map.Entry<Function,List<String>> e: hits.entrySet()){
      Function f=e.getKey();
      pw.println("\n### "+(f!=null?f.getName()+" @0x"+Long.toHexString(f.getEntryPoint().getOffset())+" (size "+f.getBody().getNumAddresses()+")":"<no func>")+" ###");
      for(String s:e.getValue()) pw.println("  "+s);
      if(f!=null && f.getBody().getNumAddresses()<700){
        DecompileResults r=di.decompileFunction(f,40,monitor);
        if(r!=null&&r.decompileCompleted()){ pw.println("  --- decompile ---");
          String[] ls=r.getDecompiledFunction().getC().split("\n");
          for(int i=0;i<Math.min(ls.length,55);i++) pw.println("  "+ls[i]); }
      }
    }
    pw.close(); println("wrote re/freelist.txt ("+hits.size()+" functions)");
  }
}
