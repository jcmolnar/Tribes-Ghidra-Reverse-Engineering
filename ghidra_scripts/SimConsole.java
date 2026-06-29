// RE SimConsoleEvent::unpack (tag 1032) in T1Vista, accounting for the vtable label-shift.
// Find the "SimConsoleEvent" descriptor (string-0x30); the vtable V whose +0x1c points to it is the
// dump-labeled (predecessor) one, so the REAL SimConsoleEvent vtable = V + 0x34. Decompile its unpack/pack.
// Also decompile the predecessor's unpack (what the naive dump mislabels) so we can pick the right one by
// matching the live wire bits the other window captured: argc + huffman readStrings.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.app.decompiler.*;

public class SimConsole extends GhidraScript {
  Memory mem; AddressSpace sp; FunctionManager fm; DecompInterface di;
  long u32(long va) throws MemoryAccessException { return mem.getInt(sp.getAddress(va)) & 0xffffffffL; }
  String nameAt(long va){
    try{ StringBuilder s=new StringBuilder(); Address a=sp.getAddress(va);
      for(int i=0;i<48;i++){int b=mem.getByte(a.add(i))&0xff; if(b==0)break;
        boolean ok=(b>='A'&&b<='Z')||(b>='a'&&b<='z')||(b>='0'&&b<='9')||b=='_'||b==':'; if(!ok)return null; s.append((char)b);}
      String r=s.toString(); return r.length()>=4?r:null;
    }catch(Exception e){return null;}
  }
  String realName(long vt){ try{ return nameAt(u32((vt-0x34)+0x1c)+0x30); }catch(Exception e){ return null; } }
  String deco(long v){
    Address pa=sp.getAddress(v); Function f=fm.getFunctionAt(pa); if(f==null)f=fm.getFunctionContaining(pa);
    if(f==null){ try{disassemble(pa); f=createFunction(pa,null);}catch(Exception e){} }
    if(f==null) return "  <no func @0x"+Long.toHexString(v)+">";
    DecompileResults r=di.decompileFunction(f,90,monitor);
    return (r!=null&&r.decompileCompleted())? r.getDecompiledFunction().getC() : "  <fail>";
  }
  public void run() throws Exception {
    mem=currentProgram.getMemory(); sp=currentProgram.getAddressFactory().getDefaultAddressSpace();
    fm=currentProgram.getFunctionManager(); di=new DecompInterface(); di.openProgram(currentProgram);

    Address na=mem.findBytes(currentProgram.getMinAddress(), "SimConsoleEvent".getBytes("ASCII"), null, true, monitor);
    if(na==null){ println("SimConsoleEvent string not found"); return; }
    long descr=na.getOffset()-0x30;
    println("SimConsoleEvent string@0x"+Long.toHexString(na.getOffset())+" descr=0x"+Long.toHexString(descr));

    // find vtable V with *(V+0x1c)==descr (the dump-labeled/predecessor vtable)
    long predVt=0;
    for(MemoryBlock b: mem.getBlocks()){
      if(!b.isInitialized()) continue;
      long s=b.getStart().getOffset(), e=b.getEnd().getOffset()-0x20;
      for(long V=s; V<=e; V+=4){
        try{ if(u32(V+0x1c)==descr){ predVt=V; break; } }catch(Exception ex){}
      }
      if(predVt!=0) break;
    }
    println("predecessor vtable (dump-labeled SimConsoleEvent) = 0x"+Long.toHexString(predVt));
    long realVt=predVt+0x34;
    println("REAL SimConsoleEvent vtable = 0x"+Long.toHexString(realVt)+"  realName="+realName(realVt));
    long unpack=u32(realVt+0x10), pack=u32(realVt+0x0c);
    println("  pack=0x"+Long.toHexString(pack)+"  unpack=0x"+Long.toHexString(unpack));

    println("\n################ REAL SimConsoleEvent::unpack @0x"+Long.toHexString(unpack)+" ################");
    println(deco(unpack));
    println("\n################ (predecessor's unpack @0x"+Long.toHexString(u32(predVt+0x10))+", the mislabel) ################");
    println(deco(u32(predVt+0x10)));
  }
}
