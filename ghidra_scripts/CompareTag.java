// Find the tag-field offset in the persistent descriptor by comparing known events (PlayerAddEvent=1099,
// PlayerSayEvent=1107, TeamAddEvent=1103) with TeamObjectiveEvent. Tag may be stored full (1024+N) or as
// the 7-bit wire value (N = tag-1024). Dump descriptor words and flag any matching a known tag/wire value.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.mem.*;

public class CompareTag extends GhidraScript {
  Memory mem; AddressSpace sp;
  Address findStr(String s) throws Exception {
    return mem.findBytes(currentProgram.getMinAddress(), s.getBytes("ASCII"), null, true, monitor);
  }
  public void run() throws Exception {
    mem=currentProgram.getMemory(); sp=currentProgram.getAddressFactory().getDefaultAddressSpace();
    String[] names={"PlayerAddEvent","PlayerSayEvent","TeamAddEvent","TeamObjectiveEvent","PlayerRemoveEvent"};
    int[] known   ={1099,            1107,           1103,          -1,                  1100};
    for(int k=0;k<names.length;k++){
      Address nm=findStr(names[k]);
      if(nm==null){ println(names[k]+": <not found>"); continue; }
      long base=nm.getOffset();
      println("\n=== "+names[k]+"  name@0x"+Long.toHexString(base)+"  knownTag="+known[k]+
              (known[k]>0?(" wire="+(known[k]-1024)):"")+" ===");
      // dump the 0x40 bytes before the name (the descriptor fields) as words
      for(long d=-0x3c; d<=0; d+=4){
        try{ int v=mem.getInt(sp.getAddress(base+d)); long uv=v&0xffffffffL;
          String tagHint="";
          if(uv>=1024 && uv<=1151) tagHint=" <== TAG? (full "+uv+")";
          else if(uv<128 && uv>0 && (uv+1024>=1099)) tagHint=" <== wire? (->"+(uv+1024)+")";
          println(String.format("   [name%+d] = 0x%08x (%d)%s", d, uv, (int)v, tagHint));
        }catch(Exception e){}
      }
    }
  }
}
