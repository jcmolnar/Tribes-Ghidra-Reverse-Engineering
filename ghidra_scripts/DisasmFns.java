// DisasmFns — dump full disassembly of given functions (Tribes.exe, base 0x400000).
// Target: advanceToTime FUN_0051e710 (find eventQueue offset via the ECX setup before the
// pop call FUN_0051dfd0) + server loop FUN_004e8ee0 (find the advanceToTime call site / hook).
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import java.io.*;

public class DisasmFns extends GhidraScript {
  public void run() throws Exception {
    AddressSpace sp=currentProgram.getAddressFactory().getDefaultAddressSpace();
    Listing lst=currentProgram.getListing();
    long[] addrs = {0x423158L, 0x40b788L};   // console-registration (hook for addCommand) + addClient pool-pop (hook for reserved-skip)
    PrintWriter pw=new PrintWriter(new BufferedWriter(new FileWriter(
      "C:\\Users\\Joe\\Desktop\\Tribes Browser Based\\re\\disasm_freeze.txt")));
    for(long va:addrs){
      Address a=sp.getAddress(va);
      Function f=currentProgram.getFunctionManager().getFunctionContaining(a);
      pw.println("======================================================");
      pw.println("=== FUN_0x"+Long.toHexString(va)+(f!=null?(" "+f.getName()):"")+" ===");
      Address cur=a;
      for(int i=0;i<520;i++){
        Instruction ins=lst.getInstructionAt(cur);
        if(ins==null) break;
        String tgt="";
        // annotate call/jump targets
        if(ins.getFlowType().isCall()||ins.getFlowType().isJump()){
          Address[] fl=ins.getFlows();
          if(fl!=null&&fl.length>0) tgt="   -> 0x"+Long.toHexString(fl[0].getOffset());
        }
        pw.println(String.format("  0x%08x  %-34s%s", cur.getOffset(), ins.toString(), tgt));
        cur=cur.add(ins.getLength());
        // stop at function end (RET) if we've left the function
        if(f!=null && !f.getBody().contains(cur)) break;
      }
      pw.println();
    }
    pw.close();
    println("wrote re/disasm_freeze.txt");
  }
}
