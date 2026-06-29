// Probe140b — identify the pack/unpack vtable slots by decompiling candidate overrides of known classes.
// TeamObjectiveEvent unpack is known (read objNum:32 + readString); whichever candidate matches = the unpack slot.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.app.decompiler.*;
import java.io.*;

public class Probe140b extends GhidraScript {
  FunctionManager fm; DecompInterface di; AddressSpace sp; PrintWriter pw;
  void deco(String label, long ea) throws Exception {
    pw.println("\n================ "+label+" @0x"+Long.toHexString(ea)+" ================");
    Address a=sp.getAddress(ea); Function f=fm.getFunctionAt(a); if(f==null)f=fm.getFunctionContaining(a);
    if(f==null){ try{disassemble(a); f=createFunction(a,null);}catch(Exception e){} }
    if(f==null){ pw.println("  <no func>"); return; }
    DecompileResults r=di.decompileFunction(f,60,monitor);
    pw.println((r!=null&&r.decompileCompleted())? r.getDecompiledFunction().getC() : "  <fail>");
  }
  public void run() throws Exception {
    fm=currentProgram.getFunctionManager(); sp=currentProgram.getAddressFactory().getDefaultAddressSpace();
    di=new DecompInterface(); di.openProgram(currentProgram);
    pw=new PrintWriter(new BufferedWriter(new FileWriter(System.getProperty("user.home")+"/probe140b.txt")));
    // TeamObjectiveEvent per-class slots 3,6,7
    deco("TeamObjectiveEvent slot3", 0x4b47f0L);
    deco("TeamObjectiveEvent slot6", 0x4b4800L);
    deco("TeamObjectiveEvent slot7", 0x4b4840L);
    // PlayerSayEvent per-class slots 3,6,7 (chat: sender:12, msgType:5, readString)
    deco("PlayerSayEvent slot3", 0x4b4660L);
    deco("PlayerSayEvent slot6", 0x4b4670L);
    deco("PlayerSayEvent slot7", 0x4b46b0L);
    // BulletData candidate unpack slots 3,4
    deco("BulletData slot3", 0x4c0a20L);
    deco("BulletData slot4", 0x4ca520L);
    // Persistent base candidates (expect tiny version stubs)
    deco("base 0x413460", 0x413460L);
    deco("base 0x413470", 0x413470L);
    deco("base 0x413480", 0x413480L);
    deco("base 0x4134b0", 0x4134b0L);
    pw.close(); println("wrote re\\probe140b.txt");
  }
}
