// SliderVt2 — FGSlider primary vtable is 0x61f2dc (from the ctor storing PTR_FUN_0061f2dc).
// Dump every slot and decompile the ones that touch the stream / write numDiscreteValues (+0x1e8).
// Identify read()/write() and read the exact field byte-widths. Output: re/slider_vt2.txt
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.app.decompiler.*;
import java.io.*;

public class SliderVt2 extends GhidraScript {
  Memory mem; FunctionManager fm; AddressSpace sp; DecompInterface di; PrintWriter pw;
  String dc(long va){
    try{ Address pa=sp.getAddress(va); Function f=fm.getFunctionAt(pa);
      if(f==null){ disassemble(pa); f=createFunction(pa,null); if(f==null)f=fm.getFunctionContaining(pa);}
      if(f==null)return "  <no fn>";
      DecompileResults r=di.decompileFunction(f,70,monitor);
      return (r!=null&&r.decompileCompleted())?r.getDecompiledFunction().getC():"  <fail>";
    }catch(Exception e){return "  <exc "+e+">";}
  }
  public void run() throws Exception {
    mem=currentProgram.getMemory(); fm=currentProgram.getFunctionManager();
    sp=currentProgram.getAddressFactory().getDefaultAddressSpace();
    di=new DecompInterface(); di.openProgram(currentProgram);
    pw=new PrintWriter(new BufferedWriter(new FileWriter(
      "C:\\Users\\Joe\\Desktop\\Tribes Browser Based\\re\\slider_vt2.txt")));
    long[] vts={0x61f2dcL, 0x629538L};
    for(long vt:vts){
      pw.println("\n########## vtable 0x"+Long.toHexString(vt)+" ##########");
      for(int j=0;j<60;j++){
        long s; try{ s=mem.getInt(sp.getAddress(vt+j*4L))&0xffffffffL; }catch(Exception e){break;}
        if(s<0x401000L||s>=0x60e000L){ pw.println("  slot["+j+"]=0x"+Long.toHexString(s)+" (end)"); break; }
        Function f=fm.getFunctionAt(sp.getAddress(s));
        pw.println(String.format("  slot[%2d]=0x%08x %s",j,s,f!=null?f.getName():""));
      }
      for(int j=0;j<60;j++){
        long s; try{ s=mem.getInt(sp.getAddress(vt+j*4L))&0xffffffffL; }catch(Exception e){break;}
        if(s<0x401000L||s>=0x60e000L) break;
        pw.println("\n==== slot["+j+"] @0x"+Long.toHexString(s)+" ====");
        pw.println(dc(s));
      }
    }
    pw.close(); println("wrote re/slider_vt2.txt");
  }
}
