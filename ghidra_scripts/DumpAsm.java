// DumpAsm — disassemble the keyboard-dispatch function in T1Vista.exe so we can
// read the EXACT register/stack setup for its evaluate (0x5f41a8) and findMatch
// (0x5090..) calls, to mirror the Borland ABI byte-for-byte in the plugin.
// Output: re/asm_keydispatch_T1Vista.txt
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import java.io.*;

public class DumpAsm extends GhidraScript {
  public void run() throws Exception {
    if(!currentProgram.getName().equalsIgnoreCase("T1Vista.exe")){ println("run on T1Vista.exe"); return; }
    PrintWriter pw=new PrintWriter(new BufferedWriter(new FileWriter(
      System.getProperty("user.home")+"/asm_keydispatch_T1Vista.txt")));
    Listing lst=currentProgram.getListing();
    Address a=toAddr(0x0050d62cL), end=toAddr(0x0050d710L);
    pw.println("##### FUN_0050d62c disasm (keyboard->bind dispatch) #####");
    Instruction ins=lst.getInstructionAt(a);
    while(ins!=null && ins.getAddress().compareTo(end) < 0){
      StringBuilder b=new StringBuilder();
      byte[] by=ins.getBytes();
      for(byte x:by) b.append(String.format("%02X ", x & 0xff));
      String tgt="";
      Reference[] rs=ins.getReferencesFrom();
      for(Reference r:rs) if(r.getReferenceType().isCall()||r.getReferenceType().isJump())
        tgt="  -> 0x"+Long.toHexString(r.getToAddress().getOffset());
      pw.println(String.format("0x%08x  %-22s %s%s",
        ins.getAddress().getOffset(), b.toString().trim(), ins.toString(), tgt));
      ins=ins.getNext();
    }
    pw.close();
    println("DumpAsm: wrote re/asm_keydispatch_T1Vista.txt");
  }
}
