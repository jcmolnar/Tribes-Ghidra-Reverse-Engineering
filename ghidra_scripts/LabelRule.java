// Find a STRIDE-INDEPENDENT label rule so ALL 232 persistent classes can be named correctly (not just the
// equal-sized SimEvent vtables). Hypothesis: *(V+0x1c) points to the PREVIOUS class's descriptor, descriptors
// are uniformly spaced, so realName(V) = string at *(V+0x1c) + DELTA + 0x30 for some constant DELTA (descriptor
// size). Test several candidate DELTAs against content-known anchors + the SimEvent cluster (where V-0x34 is known
// correct), and report which DELTA reproduces the correct names everywhere.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.mem.*;

public class LabelRule extends GhidraScript {
  Memory mem; AddressSpace sp;
  long u32(long va) throws MemoryAccessException { return mem.getInt(sp.getAddress(va)) & 0xffffffffL; }
  String nameAt(long va){
    try{ StringBuilder s=new StringBuilder(); Address a=sp.getAddress(va);
      for(int i=0;i<48;i++){int b=mem.getByte(a.add(i))&0xff; if(b==0)break;
        boolean ok=(b>='A'&&b<='Z')||(b>='a'&&b<='z')||(b>='0'&&b<='9')||b=='_'||b==':'; if(!ok)return null; s.append((char)b);}
      String r=s.toString(); return r.length()>=3?r:null;}catch(Exception e){return null;}
  }
  // V-0x34 reference name (known correct for SimEvent cluster)
  String ref(long vt){ try{ return nameAt(u32((vt-0x34)+0x1c)+0x30); }catch(Exception e){ return null; } }
  // candidate: *(V+0x1c)+delta+0x30
  String cand(long vt, long delta){ try{ return nameAt(u32(vt+0x1c)+delta+0x30); }catch(Exception e){ return null; } }

  public void run() throws Exception {
    mem=currentProgram.getMemory(); sp=currentProgram.getAddressFactory().getDefaultAddressSpace();
    // content-known anchors: vtable -> expected real name
    long[][] anchors = {
      {0x0060faf8L,0}, {0x0060fac4L,0}, {0x0060f9f4L,0},   // PingPL, DeltaScore, TeamObjective (SimEvent cluster)
    };
    long[] deltas = {0x5c, 0x58, 0x60, 0x54, 0x50, 0x64};
    println("=== SimEvent cluster: ref(V-0x34) vs cand(*(V+0x1c)+delta) ===");
    for(long vt=0x0060f820L; vt<=0x0060fb60L; vt+=0x34){
      long s0; try{ s0=u32(vt);}catch(Exception e){continue;}
      if(s0!=0x0058b794L) continue;
      String r=ref(vt);
      StringBuilder sb=new StringBuilder();
      for(long d: deltas){ String c=cand(vt,d); sb.append(String.format("  d%02x=%s", d, c==null?"-":c)); }
      println(String.format("0x%08x ref=%-24s |%s", vt, r==null?"?":r, sb.toString()));
    }
    // also test on a NON-SimEvent class: find "PlayerData" descriptor's owning vtable region.
    println("\n=== non-SimEvent probe: scan a few vtables near the datablock region (0x619000-0x61e500) ===");
    int shown=0;
    for(long vt=0x00619000L; vt<=0x0061e500L && shown<8; vt+=4){
      long pk,up,descr; try{ pk=u32(vt+0x0c); up=u32(vt+0x10); descr=u32(vt+0x1c);}catch(Exception e){continue;}
      if(pk<0x401000L||pk>=0x60e000L||up<0x401000L||up>=0x60e000L) continue;
      String naive=nameAt(descr+0x30);
      if(naive==null) continue;
      StringBuilder sb=new StringBuilder();
      for(long d: deltas){ String c=cand(vt,d); sb.append(String.format("  d%02x=%s", d, c==null?"-":c)); }
      println(String.format("0x%08x naive=%-24s |%s", vt, naive, sb.toString()));
      shown++;
    }
  }
}
