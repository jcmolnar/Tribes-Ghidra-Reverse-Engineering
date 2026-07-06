// FindTagStores — scan .text for `C7 05 <dest32> <imm32>` (MOV dword[dest],imm) where imm is a GUI
// FOURCC tag. dest = rep+0x90 (tag field). rep = dest-0x90; descriptor vtable = *rep; persist
// read=descVt[6], write=descVt[7]. This recovers the authoritative tag->read map regardless of
// function analysis. Decompile distinct reads. Output: re/tag_stores.txt
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.app.decompiler.*;
import java.io.*;
import java.util.*;

public class FindTagStores extends GhidraScript {
  Memory mem; FunctionManager fm; AddressSpace sp; DecompInterface di; PrintWriter pw;
  long slot(long vt,int i){ try{ return mem.getInt(sp.getAddress(vt+i*4L))&0xffffffffL; }catch(Exception e){ return 0; } }
  boolean code(long v){ return v>=0x401000L && v<0x60e000L; }
  int u8(long a){ try{ return mem.getByte(sp.getAddress(a))&0xff; }catch(Exception e){ return -1; } }
  long u32(long a){ try{ return mem.getInt(sp.getAddress(a))&0xffffffffL; }catch(Exception e){ return -1; } }
  boolean tagLike(long v){ // 4 printable ascii, first is F/S/M
    for(int i=0;i<4;i++){ int c=(int)((v>>(8*i))&0xff); if(c<0x30||c>0x7a) return false; }
    int c0=(int)(v&0xff); return c0=='F'||c0=='S'||c0=='M';
  }
  String tagStr(long v){ StringBuilder b=new StringBuilder(); for(int i=0;i<4;i++) b.append((char)((v>>(8*i))&0xff)); return b.toString(); }
  String dc(long va){
    try{ Address pa=sp.getAddress(va); Function f=fm.getFunctionAt(pa);
      if(f==null){ disassemble(pa); f=createFunction(pa,null); if(f==null)f=fm.getFunctionContaining(pa);}
      if(f==null)return "  <no fn>";
      DecompileResults r=di.decompileFunction(f,80,monitor);
      return (r!=null&&r.decompileCompleted())?r.getDecompiledFunction().getC():"  <fail>";
    }catch(Exception e){return "  <exc "+e+">";}
  }
  public void run() throws Exception {
    mem=currentProgram.getMemory(); fm=currentProgram.getFunctionManager();
    sp=currentProgram.getAddressFactory().getDefaultAddressSpace();
    di=new DecompInterface(); di.openProgram(currentProgram);
    pw=new PrintWriter(new BufferedWriter(new FileWriter(
      "C:\\Users\\Joe\\Desktop\\Tribes Browser Based\\re\\tag_stores.txt")));
    TreeMap<String,long[]> map=new TreeMap<>(); // tag -> {rep,descVt,read,write}
    for(MemoryBlock b: mem.getBlocks()){
      if(!b.isInitialized() || !b.isExecute()) continue;
      long s=b.getStart().getOffset(), e=b.getEnd().getOffset();
      for(long a=s; a+10<=e+1; a++){
        if(u8(a)!=0xC7 || u8(a+1)!=0x05) continue;
        long dest=u32(a+2), imm=u32(a+6);
        if(dest<0 || imm<0) continue;
        if(!tagLike(imm)) continue;
        long rep=dest-0x90;
        // scan backward up to 80 bytes for `C7 05 <rep> <descVt>` (MOV [rep], descriptorVtable)
        long dvt=0;
        for(long back=a-6; back>=a-80; back--){
          if(u8(back)==0xC7 && u8(back+1)==0x05 && u32(back+2)==rep){ dvt=u32(back+6); break; }
        }
        long rd=0,wr=0; if(dvt>=0x610000L && dvt<0x670000L){ rd=slot(dvt,6); wr=slot(dvt,7); }
        map.put(tagStr(imm), new long[]{rep,dvt,rd,wr});
      }
    }
    pw.println("######## ALL persist tag stores (C7 05 dest,tag) -> rep/desc/read/write ########");
    TreeMap<Long,String> reads=new TreeMap<>();
    for(Map.Entry<String,long[]> en:map.entrySet()){ long[] m=en.getValue();
      pw.println(String.format("%-5s : rep=%08x descVt=%08x read=%08x write=%08x",
        en.getKey(),m[0],m[1],m[2],m[3]));
      if(code(m[2])) reads.put(m[2],(reads.containsKey(m[2])?reads.get(m[2])+", ":"")+en.getKey());
    }
    pw.println("\n\n######## DISTINCT AUTHORITATIVE READS ########");
    for(Map.Entry<Long,String> en:reads.entrySet()){
      pw.println("\n======== read 0x"+Long.toHexString(en.getKey())+"  ["+en.getValue()+"] ========");
      pw.println(dc(en.getKey())); }
    pw.close(); println("wrote re/tag_stores.txt  tags="+map.size());
  }
}
