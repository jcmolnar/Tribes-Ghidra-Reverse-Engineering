// DecompOne — decompile + full disasm of the functions at given addrs (Tribes.exe).
// Used to audit the ghost readPacket idx bounds + the ghost-array allocation size.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.app.decompiler.*;
import java.io.*;

public class DecompOne extends GhidraScript {
  public void run() throws Exception {
    AddressSpace sp=currentProgram.getAddressFactory().getDefaultAddressSpace();
    Listing lst=currentProgram.getListing();
    long[] addrs={0x423158L};   // find its CALLER below; decompile to see where gameObj (the namespace src) comes from
    DecompInterface di=new DecompInterface(); di.openProgram(currentProgram);
    PrintWriter pw=new PrintWriter(new BufferedWriter(new FileWriter(
      "C:\\Users\\Joe\\Desktop\\Tribes Browser Based\\re\\decompone.txt")));
    for(long va:addrs){
      Address a=sp.getAddress(va);
      Function f=currentProgram.getFunctionManager().getFunctionContaining(a);
      pw.println("================ 0x"+Long.toHexString(va)+(f!=null?" "+f.getName():"")+" ================");
      if(f!=null){
        DecompileResults r=di.decompileFunction(f,90,monitor);
        if(r!=null&&r.decompileCompleted()){ pw.println("--- decompile ---"); pw.println(r.getDecompiledFunction().getC()); }
        pw.println("--- disasm ---");
        Address cur=f.getEntryPoint();
        for(int i=0;i<400;i++){ Instruction ins=lst.getInstructionAt(cur); if(ins==null) break;
          String s=ins.toString(); String tag="";
          if(s.contains("0x517eb0")) tag="  <-- getGhost";
          if(s.startsWith("CALL")&&s.contains("0x40fd")) tag="  <-- readInt";
          pw.println(String.format("  0x%08x  %-34s%s",cur.getOffset(),s,tag));
          cur=cur.add(ins.getLength()); if(!f.getBody().contains(cur)) break;
        }
      }
      pw.println();
    }
    pw.close(); println("wrote re/decompone.txt");
  }
}
