// CrashVec — decompile the catalog wire-data crash-vector functions in 1.40 + dump disassembly so we
// can find the exact NULL-deref instruction (hook address) + the register holding the maybe-NULL pointer.
// Output: re/crashvec.txt
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.app.decompiler.*;
import ghidra.program.model.mem.*;
import java.io.*;

public class CrashVec extends GhidraScript {
  DecompInterface di; FunctionManager fm; AddressSpace sp; Memory mem; Listing lst; PrintWriter pw;
  long u32(long va) throws Exception { return mem.getInt(sp.getAddress(va)) & 0xffffffffL; }
  void dump(String name, long fa){
    pw.println("\n#################### "+name+" @0x"+Long.toHexString(fa)+" ####################");
    Function f=fm.getFunctionContaining(sp.getAddress(fa));
    if(f==null){ pw.println("  <no function>"); return; }
    DecompileResults r=di.decompileFunction(f,90,monitor);
    pw.println("---- decompile ----");
    pw.println((r!=null&&r.decompileCompleted())? r.getDecompiledFunction().getC():"  <fail>");
    pw.println("---- disassembly ----");
    Address a=f.getEntryPoint(); Address end=f.getBody().getMaxAddress();
    int n=0;
    while(a!=null && a.compareTo(end)<=0 && n<400){
      Instruction ins=lst.getInstructionAt(a);
      if(ins==null){ a=a.add(1); continue; }
      String op=ins.toString();
      // flag interesting lines (calls, derefs of small offsets, tests)
      String mark="";
      if(op.startsWith("CALL")) mark="   ; CALL";
      pw.println(String.format("  0x%08x  %s%s", a.getOffset(), op, mark));
      a=ins.getAddress().add(ins.getLength()); n++;
    }
  }
  public void run() throws Exception {
    di=new DecompInterface(); di.openProgram(currentProgram);
    fm=currentProgram.getFunctionManager(); sp=currentProgram.getAddressFactory().getDefaultAddressSpace();
    mem=currentProgram.getMemory(); lst=currentProgram.getListing();
    pw=new PrintWriter(new BufferedWriter(new FileWriter("C:\\Users\\Joe\\Desktop\\Tribes Browser Based\\re\\crashvec.txt")));
    // known
    dump("DataBlockEvent::unpack (createDataBlock NULL)", 0x434fa0L);
    dump("Player::unpackUpdate (resolveGhost NULL on MountMask)", 0x4bc8c0L);
    // RemoteCreateEvent::unpack = slot 7 of Net::RemoteCreateEvent vtable 0x66571c
    long rce=u32(0x66571cL + 7*4L);
    dump("Net::RemoteCreateEvent::unpack slot7 (Persistent::create NULL)", rce);
    // Lightning::unpackUpdate = slot 26 of Lightning ghost vtable 0x65e4dc
    long lun=u32(0x65e4dcL + 26*4L);
    dump("Lightning::unpackUpdate slot26 (resolveGhost NULL)", lun);
    pw.close();
    println("wrote re/crashvec.txt  RCE::unpack=0x"+Long.toHexString(rce)+"  Lightning::unpackUpdate=0x"+Long.toHexString(lun));
  }
}
