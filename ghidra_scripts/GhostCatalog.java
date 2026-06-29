// GHOST CATALOG: dump unpackUpdate (the live per-frame world-state decoder) for every ghost class.
// GhostManager::readPacket (FUN_00552cc8) calls (*obj+0x68)(obj, ghostMgr, stream) after create(readInt(10)).
// So unpackUpdate = *(vtable+0x68). Enumerate persistent vtables; any whose +0x68 points into .text is a ghost
// (SimNetObject subclass) -> decompile its unpackUpdate. Names via the same SimEvent-shift / naive rule.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.app.decompiler.*;
import java.util.*;

public class GhostCatalog extends GhidraScript {
  Memory mem; AddressSpace sp; FunctionManager fm; DecompInterface di;
  long textMin,textMax; static final long SE=0x0058b794L;
  long u32(long va) throws MemoryAccessException { return mem.getInt(sp.getAddress(va))&0xffffffffL; }
  boolean inText(long v){ return v>=textMin && v<textMax; }
  String nameAt(long va){ try{ StringBuilder s=new StringBuilder(); Address a=sp.getAddress(va);
    for(int i=0;i<60;i++){int b=mem.getByte(a.add(i))&0xff; if(b==0)break;
      boolean ok=(b>='A'&&b<='Z')||(b>='a'&&b<='z')||(b>='0'&&b<='9')||b=='_'||b==':'; if(!ok)return null; s.append((char)b);}
    String r=s.toString(); if(r.length()<3)return null; char c=r.charAt(0); if(c<'A'||c>'Z')return null; return r;}catch(Exception e){return null;} }
  String realName(long vt){ try{ if(u32(vt)==SE){ long p=vt-0x34; if(u32(p)==SE){String n=nameAt(u32(p+0x1c)+0x30); if(n!=null)return n;} }
    return nameAt(u32(vt+0x1c)+0x30);}catch(Exception e){return null;} }
  String deco(long v){ Address pa=sp.getAddress(v); Function f=fm.getFunctionAt(pa); if(f==null)f=fm.getFunctionContaining(pa);
    if(f==null){try{disassemble(pa);f=createFunction(pa,null);}catch(Exception e){}}
    if(f==null)return "  <no func>"; DecompileResults r=di.decompileFunction(f,60,monitor);
    return (r!=null&&r.decompileCompleted())?r.getDecompiledFunction().getC():"  <fail>"; }

  public void run() throws Exception {
    mem=currentProgram.getMemory(); sp=currentProgram.getAddressFactory().getDefaultAddressSpace();
    fm=currentProgram.getFunctionManager(); di=new DecompInterface(); di.openProgram(currentProgram);
    MemoryBlock tb=mem.getBlock(".text"); textMin=tb.getStart().getOffset(); textMax=tb.getEnd().getOffset();
    // collect ghost classes: vtable with pack/unpack in .text AND a valid unpackUpdate at +0x68 in .text
    Map<String,long[]> ghosts=new TreeMap<String,long[]>();
    for(MemoryBlock b: mem.getBlocks()){
      if(!b.isInitialized()||b.getName().equals(".text")) continue;
      long s=b.getStart().getOffset(), e=b.getEnd().getOffset()-0x70;
      for(long V=s; V<=e; V+=4){
        long pk,up,uu,descr;
        try{ pk=u32(V+0x0c); up=u32(V+0x10); descr=u32(V+0x1c); uu=u32(V+0x68);}catch(Exception ex){continue;}
        if(!inText(pk)||!inText(up)||pk==0||up==0) continue;
        if(nameAt(descr+0x30)==null) continue;        // must be a persistent class
        if(!inText(uu)||uu==0) continue;               // must have a ghost unpackUpdate at +0x68
        String nm=realName(V); if(nm==null) continue;
        if(!ghosts.containsKey(nm)) ghosts.put(nm,new long[]{V,uu});
      }
    }
    println("=== "+ghosts.size()+" ghost classes (have unpackUpdate@+0x68) ===");
    java.io.PrintWriter pw=new java.io.PrintWriter(new java.io.BufferedWriter(new java.io.FileWriter(
       "C:\\Users\\Joe\\Desktop\\Tribes Browser Based\\re\\ghost_catalog.txt")));
    pw.println("GHOST CATALOG — unpackUpdate (live world-state decoder, vtable+0x68) per ghost class, T1Vista.exe.");
    pw.println("GhostManager::readPacket framing (FUN_00552cc8, matches source): ghostAlwaysFlag; idSize=readInt(3);");
    pw.println("per-ghost: readFlag hasGhost; index=readInt(idSize+3); readFlag delete; if-new {oNumber=readInt(32)");
    pw.println("if ghostAlways; tag=readInt(10); create(tag)}; (*obj+0x68)(unpackUpdate).\n");
    for(Map.Entry<String,long[]> en: ghosts.entrySet()){
      long[] v=en.getValue();
      String hdr=String.format("%-30s vtbl=0x%08x unpackUpdate=0x%08x", en.getKey(), v[0], v[1]);
      println("  "+hdr);
      pw.println("\n================================================================");
      pw.println(hdr); pw.println("---- unpackUpdate ----"); pw.println(deco(v[1]));
      monitor.checkCancelled();
    }
    pw.close();
    println("\nWrote re/ghost_catalog.txt");
  }
}
