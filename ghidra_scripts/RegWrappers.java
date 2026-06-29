// RegWrappers — ServerSidePlugin's command/var registration wrappers (called from the init vtable[0]
// over a static table) + the version constant _DAT_100021f8. This is the exact addCommand template.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.app.decompiler.*;
import java.io.*;

public class RegWrappers extends GhidraScript {
  public void run() throws Exception {
    AddressSpace sp=currentProgram.getAddressFactory().getDefaultAddressSpace();
    DecompInterface di=new DecompInterface(); di.openProgram(currentProgram);
    PrintWriter pw=new PrintWriter(new BufferedWriter(new FileWriter(
      "C:\\Users\\Joe\\Desktop\\Tribes Browser Based\\re\\regwrap.txt")));
    long[] fns={0x10007fd9L,0x10007fbeL,0x10004136L,0x1000410fL,0x100048ceL,0x10007f98L};
    for(long va:fns){
      Function f=currentProgram.getFunctionManager().getFunctionContaining(sp.getAddress(va));
      pw.println("\n===== 0x"+Long.toHexString(va)+(f!=null?" "+f.getName():"")+" =====");
      if(f!=null){ DecompileResults r=di.decompileFunction(f,60,monitor);
        if(r!=null&&r.decompileCompleted()) pw.println(r.getDecompiledFunction().getC());
      }
    }
    // version constant + the static command/var table globals
    pw.println("\n===== constants =====");
    try{ long lo=currentProgram.getMemory().getInt(sp.getAddress(0x100021f8L))&0xffffffffL;
      long hi=currentProgram.getMemory().getInt(sp.getAddress(0x100021fcL))&0xffffffffL;
      double d=Double.longBitsToDouble((hi<<32)|lo);
      pw.println(String.format("  _DAT_100021f8 (version double) = lo=0x%08x hi=0x%08x => %f",lo,hi,d));
    }catch(Exception e){ pw.println("  ver read fail "+e); }
    for(long g: new long[]{0x101935ecL,0x101935f0L,0x101935f8L,0x101935fcL}){
      try{ long v=currentProgram.getMemory().getInt(sp.getAddress(g))&0xffffffffL;
        pw.println(String.format("  *0x%08x = 0x%08x",g,v)); }catch(Exception e){}
    }
    pw.close(); println("wrote re/regwrap.txt");
  }
}
