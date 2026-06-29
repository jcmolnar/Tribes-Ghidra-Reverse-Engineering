// VtableDump — decompile the ServerSidePlugin descriptor vtable methods (@0x1000e028) + the
// command table (@0x1000a688). One of the vtable methods is the loader-invoked register routine
// that calls the engine addCommand with the namespace it's handed — the exact template we need.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.app.decompiler.*;
import java.io.*;

public class VtableDump extends GhidraScript {
  public void run() throws Exception {
    AddressSpace sp=currentProgram.getAddressFactory().getDefaultAddressSpace();
    DecompInterface di=new DecompInterface(); di.openProgram(currentProgram);
    PrintWriter pw=new PrintWriter(new BufferedWriter(new FileWriter(
      System.getProperty("user.home")+"/vtable.txt")));
    // dump the vtable: 8 function pointers at 0x1000e028
    pw.println("===== vtable @0x1000e028 (function pointers) =====");
    for(int i=0;i<8;i++){
      long va=0x1000e028L+i*4;
      try{ int fp=currentProgram.getMemory().getInt(sp.getAddress(va));
        pw.println(String.format("  [%d] @0x%08x -> 0x%08x",i,va,fp&0xffffffffL));
        Function f=currentProgram.getFunctionManager().getFunctionAt(sp.getAddress(fp&0xffffffffL));
        if(f!=null){ DecompileResults r=di.decompileFunction(f,50,monitor);
          if(r!=null&&r.decompileCompleted()){ String c=r.getDecompiledFunction().getC();
            pw.println("      --- "+f.getName()+" ---");
            for(String ln:(c.length()>2200?c.substring(0,2200):c).split("\n")) pw.println("      "+ln); } }
      }catch(Exception e){ pw.println("  ["+i+"] read fail"); }
    }
    // dump the command table region @0x1000a688
    pw.println("\n===== command table @0x1000a688 (raw 0x80 bytes) =====");
    byte[] b=new byte[0x80]; currentProgram.getMemory().getBytes(sp.getAddress(0x1000a688L),b);
    for(int i=0;i<0x80;i+=16){ StringBuilder s=new StringBuilder(String.format("  +0x%02x: ",i));
      for(int j=0;j<16;j++) s.append(String.format("%02x ",b[i+j]&0xff)); pw.println(s.toString()); }
    pw.close(); println("wrote re/vtable.txt");
  }
}
