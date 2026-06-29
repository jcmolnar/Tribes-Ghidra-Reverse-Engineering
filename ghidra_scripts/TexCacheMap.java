// TexCacheMap — pin the GL texture-cache structure in T1Vista so an animated-texture DLL can
// safely (a) find a texture by name and (b) mark it dirty. Approach: decompile the cache helpers
// (node alloc 0x578a1c, dirty-clear 0x57a868, register/lookup) and every function that references
// the cache root global DAT_006402fc, plus the bitmap-register path. Output: re/texcache.txt
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.app.decompiler.*;
import java.io.*;
import java.util.*;

public class TexCacheMap extends GhidraScript {
  PrintWriter pw; DecompInterface di; AddressSpace sp; Memory mem; FunctionManager fm;
  String decomp(long va){
    Function f=fm.getFunctionContaining(sp.getAddress(va));
    if(f==null){ try{disassemble(sp.getAddress(va)); f=createFunction(sp.getAddress(va),null);}catch(Exception e){} }
    if(f==null) return "  <no fn @0x"+Long.toHexString(va)+">";
    DecompileResults r=di.decompileFunction(f,90,monitor);
    return "FUN_"+Long.toHexString(f.getEntryPoint().getOffset())+" (size "+f.getBody().getNumAddresses()+"):\n"
      +((r!=null&&r.decompileCompleted())?r.getDecompiledFunction().getC():"<decompile fail>");
  }
  Set<Long> fnsRefAddr(long a){
    Set<Long> s=new LinkedHashSet<Long>();
    MemoryBlock tb=mem.getBlock(".text");
    try{ byte[] buf=new byte[(int)tb.getSize()]; mem.getBytes(tb.getStart(),buf); long base=tb.getStart().getOffset();
      byte b0=(byte)(a&0xff),b1=(byte)((a>>8)&0xff),b2=(byte)((a>>16)&0xff),b3=(byte)((a>>24)&0xff);
      for(int i=0;i+3<buf.length;i++) if(buf[i]==b0&&buf[i+1]==b1&&buf[i+2]==b2&&buf[i+3]==b3){
        Function f=fm.getFunctionContaining(sp.getAddress(base+i)); if(f!=null) s.add(f.getEntryPoint().getOffset()); }
    }catch(Exception e){}
    return s;
  }
  public void run() throws Exception {
    sp=currentProgram.getAddressFactory().getDefaultAddressSpace(); mem=currentProgram.getMemory();
    fm=currentProgram.getFunctionManager();
    di=new DecompInterface(); di.openProgram(currentProgram);
    pw=new PrintWriter(new BufferedWriter(new FileWriter(System.getProperty("user.home")+"/texcache.txt")));

    pw.println("############ cache helpers ############");
    long[] helpers={0x578a1cL,0x57a868L,0x5d3578L,0x5d43c0L,0x5d3eccL};
    for(long h:helpers){ pw.println("\n======== FUN_"+Long.toHexString(h)+" ========"); pw.println(decomp(h)); }

    pw.println("\n############ functions referencing cache root 0x006402fc ############");
    Set<Long> refs=fnsRefAddr(0x006402fcL);
    pw.println("refs: "+refs);
    for(long fn:refs){ pw.println("\n################ FUN_"+Long.toHexString(fn)+" ################"); pw.println(decomp(fn)); }
    pw.close();
    println("wrote re/texcache.txt; refs="+refs);
  }
}
