// DecompVtable — decompile every slot of a vtable (address from -Dvt or hardcoded list).
// Used to build the canonical Control/ActiveCtrl/Canvas slot->method map. Output file per vtable.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.app.decompiler.*;
import java.io.*;

public class DecompVtable extends GhidraScript {
  Memory mem; FunctionManager fm; AddressSpace sp; DecompInterface di;
  long slot(long vt,int i){ try{ return mem.getInt(sp.getAddress(vt+i*4L))&0xffffffffL; }catch(Exception e){ return 0; } }
  boolean code(long v){ return v>=0x401000L && v<0x60e000L; }
  String dc(long va){
    try{ Address pa=sp.getAddress(va); Function f=fm.getFunctionAt(pa);
      if(f==null){ disassemble(pa); f=createFunction(pa,null); if(f==null)f=fm.getFunctionContaining(pa);}
      if(f==null)return "  <no fn>";
      DecompileResults r=di.decompileFunction(f,60,monitor);
      return (r!=null&&r.decompileCompleted())?r.getDecompiledFunction().getC():"  <fail>";
    }catch(Exception e){return "  <exc "+e+">";}
  }
  public void run() throws Exception {
    mem=currentProgram.getMemory(); fm=currentProgram.getFunctionManager();
    sp=currentProgram.getAddressFactory().getDefaultAddressSpace();
    di=new DecompInterface(); di.openProgram(currentProgram);
    // arg: vtableHex outfile
    String[] a=getScriptArgs();
    long vt=Long.decode("0x"+a[0]);
    String out=a[1];
    PrintWriter pw=new PrintWriter(new BufferedWriter(new FileWriter(
      "C:\\Users\\Joe\\Desktop\\Tribes Browser Based\\re\\"+out)));
    for(int i=0;i<44;i++){ long s=slot(vt,i); if(!code(s)){ pw.println("\n==== slot["+i+"] = 0x"+Long.toHexString(s)+" (non-code) ===="); continue; }
      pw.println("\n================ slot["+i+"] 0x"+Long.toHexString(s)+" ================");
      pw.println(dc(s)); }
    pw.close(); println("wrote re/"+out);
  }
}
