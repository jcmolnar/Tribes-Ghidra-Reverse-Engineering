// Disambiguate which vtable is TeamObjectiveEvent by reading the class name its descriptor (+1c) holds,
// then fully decompile that class's unpack + the readInt helper to lock down the exact wire format.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.app.decompiler.*;

public class FinalVerify extends GhidraScript {
  Memory mem; AddressSpace sp; DecompInterface di; FunctionManager fm;
  String readStr(long va){ try{ StringBuilder s=new StringBuilder(); Address a=sp.getAddress(va);
    for(int i=0;i<40;i++){int b=mem.getByte(a.add(i))&0xff; if(b==0)break; if(b<32||b>126)return "<nonstr>"; s.append((char)b);} return s.toString(); }catch(Exception e){return "<err>";} }
  long w(long va){ try{return mem.getInt(sp.getAddress(va))&0xffffffffL;}catch(Exception e){return 0;} }
  void deco(long v,String tag){ Address pa=sp.getAddress(v); Function f=fm.getFunctionAt(pa); if(f==null)f=fm.getFunctionContaining(pa);
    if(f==null){try{disassemble(pa);f=createFunction(pa,null);}catch(Exception e){}}
    println("\n################ "+tag+" @0x"+Long.toHexString(v)+" ################");
    if(f==null){println("  <no func>");return;}
    DecompileResults r=di.decompileFunction(f,60,monitor);
    println(r!=null&&r.decompileCompleted()?r.getDecompiledFunction().getC():"  <fail>"); }

  public void run() throws Exception {
    mem=currentProgram.getMemory(); fm=currentProgram.getFunctionManager();
    sp=currentProgram.getAddressFactory().getDefaultAddressSpace();
    di=new DecompInterface(); di.openProgram(currentProgram);
    long[] vts={0x0060f9c0L,0x0060f9f4L};
    for(long vt: vts){
      long descr=w(vt+0x1c);
      println("vtable 0x"+Long.toHexString(vt)+": pack=0x"+Long.toHexString(w(vt+0x0c))+
              " unpack=0x"+Long.toHexString(w(vt+0x10))+" descr=0x"+Long.toHexString(descr));
      // hunt the class name inside the descriptor (try offsets 0x20..0x40)
      for(int off=0x20; off<=0x40; off+=4){ String s=readStr(descr+off); if(s.length()>=4 && !s.equals("<nonstr>")) println("    name@+0x"+Integer.toHexString(off)+" = \""+s+"\""); }
    }
    deco(0x0040a6a0L,"FUN_0040a6a0 (recordA unpack) FULL");
    deco(0x0040a478L,"FUN_0040a478 (recordB unpack) FULL");
    deco(0x00582f70L,"FUN_00582f70 (readInt(nbits)?)");
  }
}
