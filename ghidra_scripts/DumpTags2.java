// T1Vista's ACTUAL tag->class map: the register fn (FUN_0058af38) reads the tag from classrep+0x90 (and an
// alias at +0x94) and sets fastTable[tag]=classrep. Read +0x90/+0x94 for every event class-rep, with the
// V-0x34 corrected name. This is the ground-truth tag table to compare against our FearDcl.h.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.mem.*;

public class DumpTags2 extends GhidraScript {
  Memory mem; AddressSpace sp;
  long u32(long va) throws MemoryAccessException { return mem.getInt(sp.getAddress(va)) & 0xffffffffL; }
  String nameAt(long va){
    try{ StringBuilder s=new StringBuilder(); Address a=sp.getAddress(va);
      for(int i=0;i<48;i++){int b=mem.getByte(a.add(i))&0xff; if(b==0)break;
        boolean ok=(b>='A'&&b<='Z')||(b>='a'&&b<='z')||(b>='0'&&b<='9')||b=='_'||b==':'; if(!ok)return null; s.append((char)b);}
      String r=s.toString(); if(r.length()<4)return null; char c=r.charAt(0); if(c<'A'||c>'Z')return null; return r;
    }catch(Exception e){return null;}
  }
  String realName(long vt){ try{ return nameAt(u32((vt-0x34)+0x1c)+0x30); }catch(Exception e){ return null; } }
  public void run() throws Exception {
    mem=currentProgram.getMemory(); sp=currentProgram.getAddressFactory().getDefaultAddressSpace();
    println("=== T1Vista actual tag map (classrep+0x90 = tag, +0x94 = alias) ===");
    for(long vt=0x0060f820L; vt<=0x0060fb60L; vt+=0x34){
      long slot0; try{ slot0=u32(vt); }catch(Exception e){ continue; }
      if(slot0!=0x0058b794L) continue;
      String rn=realName(vt);
      long t90, t94; try{ t90=u32(vt+0x90); t94=u32(vt+0x94);}catch(Exception e){ continue; }
      println(String.format("  %-26s classrep 0x%08x  tag(+0x90)=%d  alias(+0x94)=%d", rn==null?"<?>":rn, vt, (int)t90, (int)t94));
    }
  }
}
