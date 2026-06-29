// DropDis — full disasm of clientDropped FUN_0040c3d8 (to pick the symmetric-teardown hook site:
// right before CALL removeClient FUN_0040c314) + removeClient + SimObject::deleteObject entry confirm.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import java.io.*;

public class DropDis extends GhidraScript {
  PrintWriter pw; AddressSpace sp;
  void disasm(long va){
    Function f=getFunctionContaining(sp.getAddress(va));
    if(f==null){ pw.println("<no fn @0x"+Long.toHexString(va)+">"); return; }
    pw.println("\n##### FUN_"+Long.toHexString(f.getEntryPoint().getOffset())+" #####");
    InstructionIterator it=currentProgram.getListing().getInstructions(f.getBody(),true);
    while(it.hasNext()){ Instruction ins=it.next(); StringBuilder b=new StringBuilder();
      try{for(byte x:ins.getBytes())b.append(String.format("%02x ",x&0xff));}catch(Exception e){}
      pw.println(String.format("    0x%08x  %-22s %s",ins.getAddress().getOffset(),b.toString().trim(),ins.toString())); }
  }
  public void run() throws Exception {
    sp=currentProgram.getAddressFactory().getDefaultAddressSpace();
    pw=new PrintWriter(new BufferedWriter(new FileWriter("C:\\Users\\Joe\\Desktop\\Tribes Browser Based\\re\\dropdis.txt")));
    disasm(0x40c3d8L);   // clientDropped
    disasm(0x4fe858L);   // SimObject::deleteObject (EAX=obj)
    pw.close(); println("wrote re/dropdis.txt");
  }
}
