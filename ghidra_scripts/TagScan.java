// TagScan — AUTHORITATIVE tag->class read/write map via classRep descriptors.
// IMPLEMENT_PERSISTENT stores the FOURCC tag int at rep+0x90 (seen: _DAT_006a6c88=0x6b734746 for a
// rep based at 0x6a6bf8). Scan all DATA dwords for each known GUI tag int; rep = addr-0x90;
// descriptor vtable = *rep; persist read = descriptor[6], write = descriptor[7]. Decompile distinct
// reads/writes. This bypasses the ambiguous catalog vtables entirely. Output: re/tag_scan.txt
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.app.decompiler.*;
import java.io.*;
import java.util.*;

public class TagScan extends GhidraScript {
  Memory mem; FunctionManager fm; AddressSpace sp; DecompInterface di; PrintWriter pw;
  long slot(long vt,int i){ try{ return mem.getInt(sp.getAddress(vt+i*4L))&0xffffffffL; }catch(Exception e){ return 0; } }
  boolean code(long v){ return v>=0x401000L && v<0x60e000L; }
  long tagInt(String s){ long v=0; for(int i=0;i<4;i++) v|=((long)(s.charAt(i)&0xff))<<(8*i); return v; }
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
      "C:\\Users\\Joe\\Desktop\\Tribes Browser Based\\re\\tag_scan.txt")));
    // Every FG/SG/MM tag seen in shipped .gui files + a few extra.
    String[] tags={"FGsk","FGsl","FGst","FGcf","FGub","FGkt","FGmi","FGte","FGsj","FGbx",
      "SGsl","SGsC","SGct","FGcl","FGsb","FGsx","FGms","FGmz","FGft","FGdb","FGpu","FGmn",
      "FGcb","FGbl","FGtx","FGtl","FGpr","FGtc","FGmt","FGhi","FGhb"};
    Map<String,long[]> map=new LinkedHashMap<>(); // tag -> {repBase, descVt, read, write}
    // Scan initialized data blocks for tag dwords.
    Set<Long> want=new HashSet<>(); Map<Long,String> rev=new HashMap<>();
    for(String t:tags){ want.add(tagInt(t)); rev.put(tagInt(t),t); }
    for(MemoryBlock b: mem.getBlocks()){
      if(!b.isInitialized()) continue;
      long start=b.getStart().getOffset(), end=b.getEnd().getOffset();
      if(start<0x600000L) continue; // data lives high
      for(long a=start; a+4<=end+1; a+=4){
        long v; try{ v=mem.getInt(sp.getAddress(a))&0xffffffffL; }catch(Exception e){ continue; }
        if(want.contains(v)){
          String t=rev.get(v); long rep=a-0x90; long dvt=0,rd=0,wr=0;
          try{ dvt=mem.getInt(sp.getAddress(rep))&0xffffffffL;
               if(code(slot(dvt,6))){ rd=slot(dvt,6); wr=slot(dvt,7);} }catch(Exception e){}
          map.put(t,new long[]{rep,dvt,rd,wr});
        }
      }
    }
    pw.println("######## tag -> classRep -> descVt -> read/write ########");
    TreeMap<Long,String> reads=new TreeMap<>(), writes=new TreeMap<>();
    for(String t:tags){ long[] m=map.get(t);
      if(m==null){ pw.println(String.format("%-5s : <not found as data tag>",t)); continue; }
      pw.println(String.format("%-5s : rep=%08x descVt=%08x read=%08x write=%08x",t,m[0],m[1],m[2],m[3]));
      if(code(m[2])) reads.put(m[2],(reads.containsKey(m[2])?reads.get(m[2])+", ":"")+t);
      if(code(m[3])) writes.put(m[3],(writes.containsKey(m[3])?writes.get(m[3])+", ":"")+t);
    }
    pw.println("\n\n######## DISTINCT READS (authoritative, via descriptor slot 6) ########");
    for(Map.Entry<Long,String> e:reads.entrySet()){
      pw.println("\n======== read 0x"+Long.toHexString(e.getKey())+"  ["+e.getValue()+"] ========");
      pw.println(dc(e.getKey())); }
    pw.close(); println("wrote re/tag_scan.txt");
  }
}
