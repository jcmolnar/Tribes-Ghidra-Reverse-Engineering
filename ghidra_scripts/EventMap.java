// CORRECTED event-cluster mapper. Empirically, vtable V's descriptor pointer (V+0x1c) names the class at
// vtable V+0x34 (the labels are shifted one slot — a Borland descriptor quirk). So the REAL name of vtable V
// is the name read from the PREVIOUS vtable's descriptor: realName(V) = string at (*((V-0x34)+0x1c))+0x30.
// Verified on 3 content-known anchors (PingPL/DeltaScore/TeamObjective). The SimEvent family is a contiguous
// 0x34-stride block, so this is reliable here. Dumps real name + unpack decompile for the whole cluster.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.app.decompiler.*;

public class EventMap extends GhidraScript {
  Memory mem; AddressSpace sp; FunctionManager fm; DecompInterface di;
  long u32(long va) throws MemoryAccessException { return mem.getInt(sp.getAddress(va)) & 0xffffffffL; }
  String nameAt(long va){
    try{ StringBuilder s=new StringBuilder(); Address a=sp.getAddress(va);
      for(int i=0;i<48;i++){int b=mem.getByte(a.add(i))&0xff; if(b==0)break;
        boolean ok=(b>='A'&&b<='Z')||(b>='a'&&b<='z')||(b>='0'&&b<='9')||b=='_'||b==':'; if(!ok)return null; s.append((char)b);}
      String r=s.toString(); if(r.length()<4)return null; char c=r.charAt(0); if(c<'A'||c>'Z')return null; return r;
    }catch(Exception e){return null;}
  }
  String realName(long vt){ try{ return nameAt(u32((vt-0x34)+0x1c)+0x30); }catch(Exception e){ return null; } }
  String deco(long v){
    Address pa=sp.getAddress(v); Function f=fm.getFunctionAt(pa); if(f==null)f=fm.getFunctionContaining(pa);
    if(f==null){ try{disassemble(pa); f=createFunction(pa,null);}catch(Exception e){} }
    if(f==null) return "  <no func>";
    DecompileResults r=di.decompileFunction(f,60,monitor);
    return (r!=null&&r.decompileCompleted())? r.getDecompiledFunction().getC() : "  <fail>";
  }
  public void run() throws Exception {
    mem=currentProgram.getMemory(); sp=currentProgram.getAddressFactory().getDefaultAddressSpace();
    fm=currentProgram.getFunctionManager(); di=new DecompInterface(); di.openProgram(currentProgram);
    java.io.PrintWriter pw=new java.io.PrintWriter(new java.io.BufferedWriter(new java.io.FileWriter(
       System.getProperty("user.home")+"/event_cluster.txt")));
    // SimEvent-family vtables share +0x00=0x58b794. Walk the contiguous 0x34-stride block.
    for(long vt=0x0060f820L; vt<=0x0060fb60L; vt+=0x34){
      long slot0; try{ slot0=u32(vt); }catch(Exception e){ continue; }
      if(slot0!=0x0058b794L) continue;                 // not a SimEvent-family vtable
      long unpack; try{ unpack=u32(vt+0x10); }catch(Exception e){ continue; }
      String rn=realName(vt);
      String hdr=String.format("vtable 0x%08x  realName=%-26s pack=0x%08x unpack=0x%08x",
                                vt, rn==null?"<?>":rn, safe(vt+0x0c), unpack);
      println(hdr);
      pw.println("\n================================================================");
      pw.println(hdr); pw.println("---- unpack ----"); pw.println(deco(unpack));
      monitor.checkCancelled();
    }
    pw.close();
    println("wrote re/event_cluster.txt");
  }
  long safe(long va){ try{return u32(va);}catch(Exception e){return 0;} }
}
