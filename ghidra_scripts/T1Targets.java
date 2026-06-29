// T1Targets — decompile T1Vista.exe at each membot patch target VA, flagging the
// patched instruction, so we can infer the bug each patch fixes.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.app.decompiler.*;
import java.io.*;

public class T1Targets extends GhidraScript {
  // membot patch target VAs (from the unpacked patch table)
  static final long[] TARGETS = {
    0x5471dcL,0x44a3e2L,0x4598e5L,0x46df3dL,0x404eafL,0x4071a3L,0x4a5f98L,0x4e939dL,
    0x4ec872L,0x40d644L,0x57cf0cL,0x541241L,
    0x5d7431L,0x5d5472L,0x5d7bd0L,0x5d48b2L,0x5d82f1L,0x5d9a09L,
    0x4dcab5L,0x57abefL,0x51e5b8L,0x53f8a8L,0x56ea78L
  };
  public void run() throws Exception {
    AddressSpace sp=currentProgram.getAddressFactory().getDefaultAddressSpace();
    FunctionManager fm=currentProgram.getFunctionManager();
    Listing lst=currentProgram.getListing();
    DecompInterface di=new DecompInterface(); di.openProgram(currentProgram);
    PrintWriter pw=new PrintWriter(new BufferedWriter(new FileWriter(
      System.getProperty("user.home")+"/mem_t1targets.txt")));
    for(long t:TARGETS){
      Address a=sp.getAddress(t);
      Function f=fm.getFunctionContaining(a);
      pw.println("##################################################################");
      pw.println("### TARGET VA 0x"+Long.toHexString(t)+(f!=null?(" in "+f.getName()+" @0x"+Long.toHexString(f.getEntryPoint().getOffset())):" (NO FUNCTION)"));
      // instruction context around target
      pw.println("--- instructions around target ---");
      Address c=a.subtract(0x18);
      for(int i=0;i<24;i++){
        Instruction ins=lst.getInstructionAt(c);
        if(ins==null){ c=c.add(1); continue; }
        String mark=(ins.getAddress().getOffset()==t)?"   <<<<<<<< PATCHED HERE":"";
        pw.println(String.format("  0x%06x  %-40s%s", ins.getAddress().getOffset(), ins.toString(), mark));
        c=ins.getAddress().add(ins.getLength());
        if(c.getOffset()>t+0x10) break;
      }
      if(f!=null){
        pw.println("--- decompile ---");
        DecompileResults r=di.decompileFunction(f,90,monitor);
        pw.println((r!=null&&r.decompileCompleted())? r.getDecompiledFunction().getC():"<fail>");
      }
      pw.println();
    }
    pw.close();
    println("wrote re/mem_t1targets.txt");
  }
}
