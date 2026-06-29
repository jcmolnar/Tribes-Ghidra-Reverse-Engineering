// Read T1Vista's ACTUAL tag->class map. Persistent::create indexes fastTable @0x6bed90 by tag (entry =
// class-rep ptr). (1) dump fastTable[1024..1151] (non-zero => statically initialized). (2) regardless, each
// event class-rep (the 0x60fXXX structs EventMap named) stores its own tag as a member set in its ctor — scan
// each class-rep's first 0x40 bytes for a value in 1024..1151. Cross-ref names via the V-0x34 corrected rule.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.mem.*;

public class DumpTagTable extends GhidraScript {
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
    long FT=0x006bed90L;
    println("=== fastTable[1024..1151] @0x6bed90 (non-zero = statically initialized) ===");
    int nz=0;
    for(int tag=1024; tag<=1151; tag++){
      long e; try{ e=u32(FT + (long)tag*4); }catch(Exception ex){ continue; }
      if(e!=0){ nz++;
        String nm = realName(e);                       // if e is a class-rep, V-0x34 name
        println(String.format("  tag %d -> classrep 0x%08x %s", tag, e, nm!=null?("= "+nm):""));
      }
    }
    println("non-zero entries: "+nz+(nz==0?"  (table is runtime-populated; using class-rep tag members below)":""));

    // (2) Each event class-rep stores its tag. Walk the SimEvent-family class-reps and find the tag member.
    println("\n=== event class-reps: name (V-0x34) + any field in 1024..1151 (the registered tag) ===");
    for(long vt=0x0060f820L; vt<=0x0060fb60L; vt+=0x34){
      long slot0; try{ slot0=u32(vt); }catch(Exception e){ continue; }
      if(slot0!=0x0058b794L) continue;
      String rn=realName(vt);
      StringBuilder tags=new StringBuilder();
      for(int off=0; off<=0x40; off+=4){
        try{ long v=u32(vt+off); if(v>=1024 && v<=1151) tags.append(String.format(" [+0x%02x]=%d", off, v)); }catch(Exception e){}
      }
      println(String.format("  classrep 0x%08x %-26s tagFields:%s", vt, rn==null?"<?>":rn, tags.length()==0?" <none in struct>":tags.toString()));
    }
  }
}
