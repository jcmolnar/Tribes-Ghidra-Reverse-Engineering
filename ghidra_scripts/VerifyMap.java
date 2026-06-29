// Diagnose the vtable->name join. For content-known vtables (PingPL=0x60faf8, DeltaScore=0x60fac4,
// TeamObjective-labeled=0x60f9c0), dump slots 0..10; for every slot that points to memory whose +0x30
// is a printable class name, print it. Reveals which slot/offset gives the CORRECT name.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.mem.*;

public class VerifyMap extends GhidraScript {
  Memory mem; AddressSpace sp;
  long u32(long va) throws MemoryAccessException { return mem.getInt(sp.getAddress(va)) & 0xffffffffL; }
  String name(long va){
    try{ StringBuilder s=new StringBuilder(); Address a=sp.getAddress(va);
      for(int i=0;i<48;i++){int b=mem.getByte(a.add(i))&0xff; if(b==0)break;
        boolean ok=(b>='A'&&b<='Z')||(b>='a'&&b<='z')||(b>='0'&&b<='9')||b=='_'||b==':'; if(!ok)return null; s.append((char)b);}
      String r=s.toString(); if(r.length()<4)return null; char c=r.charAt(0); if(c<'A'||c>'Z')return null; return r;
    }catch(Exception e){return null;}
  }
  void probe(long vt, String expect){
    println("\n=== vtable 0x"+Long.toHexString(vt)+"  (content = "+expect+") ===");
    for(int i=0;i<11;i++){
      long slot=vt+i*4L; long val;
      try{ val=u32(slot); }catch(Exception e){ break; }
      // is val a pointer whose +0x30 is a name? (descriptor candidate)
      String nm=name(val+0x30);
      String tag = (nm!=null) ? ("  -> descr? +0x30 name=\""+nm+"\"") : "";
      println(String.format("  [+0x%02x] = 0x%08x%s", i*4, val, tag));
    }
  }
  public void run() throws Exception {
    mem=currentProgram.getMemory(); sp=currentProgram.getAddressFactory().getDefaultAddressSpace();
    probe(0x0060faf8L, "PingPLEvent (count+loop{7,8,float6})");
    probe(0x0060fac4L, "DeltaScoreEvent (flag,4/7,32,string)");
    probe(0x0060f9c0L, "labeled TeamObjectiveEvent");
    // Also: find the descriptor that actually has name "PingPLEvent" and "TeamObjectiveEvent",
    // then see which vtable's unpack(+0x10) we'd get if +0x1c pointed to it.
    for(String want : new String[]{"PingPLEvent","DeltaScoreEvent","TeamObjectiveEvent","MissionResetEvent"}){
      Address na=mem.findBytes(currentProgram.getMinAddress(), want.getBytes("ASCII"), null, true, monitor);
      if(na==null){ println("\n["+want+"] string not found"); continue; }
      long descr=na.getOffset()-0x30;
      println("\n["+want+"] string@0x"+Long.toHexString(na.getOffset())+" => descr=0x"+Long.toHexString(descr));
    }
  }
}
