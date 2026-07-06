// TagRead — for slider/key tags, follow classRep descriptor -> create() -> object vtable ->
// slot0 persist read / slot1 write, decompiled. Descriptor vtables: FGsk=0x62980c, FGst=0x629778,
// FGms=0x62abb8. Dump each descriptor vtable's slots, decompile the create-like slots, and dump the
// FGSlider method cluster around 0x4ca020 & 0x4c9xxx to locate the true read. Output: re/tag_read.txt
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.app.decompiler.*;
import java.io.*;

public class TagRead extends GhidraScript {
  Memory mem; FunctionManager fm; AddressSpace sp; DecompInterface di; PrintWriter pw;
  long slot(long vt,int i){ try{ return mem.getInt(sp.getAddress(vt+i*4L))&0xffffffffL; }catch(Exception e){ return 0; } }
  boolean code(long v){ return v>=0x401000L && v<0x60e000L; }
  String dc(long va){
    try{ Address pa=sp.getAddress(va); Function f=fm.getFunctionAt(pa);
      if(f==null){ disassemble(pa); f=createFunction(pa,null); if(f==null)f=fm.getFunctionContaining(pa);}
      if(f==null)return "  <no fn>";
      DecompileResults r=di.decompileFunction(f,80,monitor);
      return (r!=null&&r.decompileCompleted())?r.getDecompiledFunction().getC():"  <fail>";
    }catch(Exception e){return "  <exc "+e+">";}
  }
  void vt(String nm,long base,int n){
    pw.println("\n---- descriptor vtable "+nm+" 0x"+Long.toHexString(base)+" ----");
    for(int i=0;i<n;i++){ long s=slot(base,i); Function f=code(s)?fm.getFunctionAt(sp.getAddress(s)):null;
      pw.println(String.format("  slot[%2d]=%08x %s",i,s,f!=null?f.getName():"")); }
  }
  public void run() throws Exception {
    mem=currentProgram.getMemory(); fm=currentProgram.getFunctionManager();
    sp=currentProgram.getAddressFactory().getDefaultAddressSpace();
    di=new DecompInterface(); di.openProgram(currentProgram);
    pw=new PrintWriter(new BufferedWriter(new FileWriter(
      "C:\\Users\\Joe\\Desktop\\Tribes Browser Based\\re\\tag_read.txt")));
    long[] descs={0x62980cL,0x629778L,0x62abb8L};
    String[] dn={"FGsk/FGSlider","FGst","FGms"};
    for(int k=0;k<descs.length;k++){
      vt(dn[k],descs[k],12);
      // create() is typically the slot pointing into code that calls operator new + ctor.
      for(int i=0;i<12;i++){ long s=slot(descs[k],i); if(code(s)){
        pw.println("\n==== "+dn[k]+" descriptor slot["+i+"] 0x"+Long.toHexString(s)+" ====");
        pw.println(dc(s)); } }
    }
    // FGSlider method cluster — decompile the persist read candidates in FGSlider's own range.
    long[] cluster={0x4ca020L,0x4c9c70L,0x4c95ccL,0x4c9160L};
    for(long f:cluster){ pw.println("\n################ cluster 0x"+Long.toHexString(f)+" ################");
      pw.println(dc(f)); }
    pw.close(); println("wrote re/tag_read.txt");
  }
}
