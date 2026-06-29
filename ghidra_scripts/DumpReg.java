// Dump the .data persistent-registration record around 0x0060f9dc (the entry whose name is
// TeamObjectiveEvent). Resolve every word; decompile every word that is/points-to a function.
// We want the create() fn (news the object + sets the real vtable that holds pack/unpack).
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.app.decompiler.*;

public class DumpReg extends GhidraScript {
  Memory mem; FunctionManager fm; AddressSpace sp; DecompInterface di;
  long TMIN=0x00401000L, TMAX=0x0060e000L;

  String classify(long v) {
    if (v < 0x400000L || v > 0x007e0000L) return "imm/0";
    Address pa = sp.getAddress(v);
    if (!mem.contains(pa)) return "unmapped";
    if (v>=TMIN && v<TMAX) {
      Function f=fm.getFunctionAt(pa); if(f==null)f=fm.getFunctionContaining(pa);
      if(f!=null) return "FUNC "+f.getName()+(f.getEntryPoint().getOffset()==v?"":"+");
      return ".text(code?)";
    }
    // try read string
    try { StringBuilder s=new StringBuilder(); for(int i=0;i<24;i++){int b=mem.getByte(pa.add(i))&0xff; if(b==0)break; if(b<32||b>126){s.setLength(0);break;} s.append((char)b);} if(s.length()>=3) return "STR \""+s+"\""; } catch(Exception e){}
    return "data";
  }
  void deco(long v, String tag){
    Address pa=sp.getAddress(v); Function f=fm.getFunctionAt(pa); if(f==null)f=fm.getFunctionContaining(pa);
    if(f==null){ try{disassemble(pa); f=createFunction(pa,null);}catch(Exception e){} }
    if(f==null){ println("  ["+tag+"] no function @ 0x"+Long.toHexString(v)); return; }
    println("\n######## "+tag+"  "+f.getName()+" @ "+f.getEntryPoint()+" ########");
    DecompileResults r=di.decompileFunction(f,45,monitor);
    println(r!=null&&r.decompileCompleted()? r.getDecompiledFunction().getC() : "  <decompile failed>");
  }

  public void run() throws Exception {
    mem=currentProgram.getMemory(); fm=currentProgram.getFunctionManager();
    sp=currentProgram.getAddressFactory().getDefaultAddressSpace();
    di=new DecompInterface(); di.openProgram(currentProgram);

    long base=0x0060f9c0L;
    println("=== .data registration record dump 0x"+Long.toHexString(base)+" ===");
    java.util.List<Long> funcs=new java.util.ArrayList<Long>();
    for(int i=0;i<28;i++){
      Address a=sp.getAddress(base+i*4L); int val; try{val=mem.getInt(a);}catch(Exception e){break;}
      long v=val&0xffffffffL; String c=classify(v);
      println(String.format("  +%02x  %s = 0x%08x  %s", i*4, a, v, c));
      if(c.startsWith("FUNC")||c.equals(".text(code?)")) funcs.add(v);
    }
    // decompile up to 4 distinct function pointers found
    java.util.LinkedHashSet<Long> uniq=new java.util.LinkedHashSet<Long>(funcs);
    int n=0; for(Long v: uniq){ deco(v,"regfn"); if(++n>=4)break; }
  }
}
