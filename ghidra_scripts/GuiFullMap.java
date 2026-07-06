// GuiFullMap — backbone of the FULL GUI RE. For every GUI persistent class:
//   tag -> classRep (C7 05 [rep+0x90],tag scan) -> descriptor vtable -> create (slot 0)
//   -> scan create's disasm for the OBJECT primary vtable it stores (imm in 0x610000..0x670000)
//   -> dump that object vtable's slots 0..44 (fn addr + name).
// Emits: (a) tag -> objVtable table, (b) per-class full vtable slot dump, (c) the DISTINCT set of
// functions across all GUI vtables (addresses only; decompiled in later passes).
// Output: re/gui_full_map.txt  + re/gui_distinct_fns.txt
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.scalar.*;
import java.io.*;
import java.util.*;

public class GuiFullMap extends GhidraScript {
  Memory mem; FunctionManager fm; AddressSpace sp; Listing lst;
  long u32(long a){ try{ return mem.getInt(sp.getAddress(a))&0xffffffffL; }catch(Exception e){ return -1; } }
  int u8(long a){ try{ return mem.getByte(sp.getAddress(a))&0xff; }catch(Exception e){ return -1; } }
  long slot(long vt,int i){ return u32(vt+i*4L); }
  boolean vtRange(long v){ return v>=0x610000L && v<0x670000L; }
  boolean code(long v){ return v>=0x401000L && v<0x60e000L; }
  boolean tagLike(long v){ for(int i=0;i<4;i++){int c=(int)((v>>(8*i))&0xff); if(c<0x30||c>0x7a) return false;} int c0=(int)(v&0xff); return c0=='F'||c0=='S'||c0=='M'; }
  String tagStr(long v){ StringBuilder b=new StringBuilder(); for(int i=0;i<4;i++) b.append((char)((v>>(8*i))&0xff)); return b.toString(); }
  String fname(long a){ Function f=code(a)?fm.getFunctionAt(sp.getAddress(a)):null; return f!=null?f.getName():""; }

  // Scan a function's raw bytes for `C7 <modrm-disp0> <vtable32>` = MOV [reg],vtable (the PRIMARY
  // object vtable at [this+0]; ignores [reg+0x6c] secondary/Responder stores). Take the LAST such
  // (base-class ctors set intermediates first, the final class overwrites). If none found and the
  // fn CALLs a ctor, follow ONE call level. Returns 0 if none.
  long objVtableFromCreate(long create){ return scanVt(create, 0); }
  long scanVt(long start, int depth){
    long found=0;
    ArrayList<Long> calls=new ArrayList<>();
    long a=start;
    for(int i=0;i<260;i++){
      int op=u8(a);
      if(op<0) break;
      if(op==0xC3||op==0xC2) break;                 // RET
      if(op==0xC7){                                  // MOV r/m32, imm32
        int modrm=u8(a+1);
        if(modrm==0x00||modrm==0x01||modrm==0x02||modrm==0x03||modrm==0x06||modrm==0x07){ // [reg] disp0
          long v=u32(a+2);
          if(vtRange(v)&&code(slot(v,0))) found=v;
          a+=6; continue;
        }
        if(modrm==0x40||modrm==0x41||modrm==0x42||modrm==0x43||modrm==0x46||modrm==0x47){ a+=7; continue; } // [reg+disp8]
      }
      if(op==0xE8){ long tgt=(a+5 + (int)u32(a+1)) & 0xffffffffL; if(code(tgt)&&tgt!=start) calls.add(tgt); }
      Instruction ins=lst.getInstructionAt(sp.getAddress(a));
      if(ins==null){ try{disassemble(sp.getAddress(a));}catch(Exception e){} ins=lst.getInstructionAt(sp.getAddress(a)); }
      a += (ins!=null)? ins.getLength() : 1;
    }
    if(found!=0) return found;
    // no direct vtable: follow calls (the ctor is usually among them), scan LAST-to-first, take first hit
    if(depth<3){
      for(int k=calls.size()-1;k>=0;k--){ long v=scanVt(calls.get(k), depth+1); if(v!=0) return v; }
    }
    return 0;
  }

  public void run() throws Exception {
    mem=currentProgram.getMemory(); fm=currentProgram.getFunctionManager();
    sp=currentProgram.getAddressFactory().getDefaultAddressSpace(); lst=currentProgram.getListing();

    // recover tag -> descVt (same C7 05 scan as FindTagStores)
    TreeMap<String,Long> tagDesc=new TreeMap<>();
    for(MemoryBlock b: mem.getBlocks()){
      if(!b.isInitialized()||!b.isExecute()) continue;
      long s=b.getStart().getOffset(), e=b.getEnd().getOffset();
      for(long a=s; a+10<=e+1; a++){
        if(u8(a)!=0xC7||u8(a+1)!=0x05) continue;
        long dest=u32(a+2), imm=u32(a+6);
        if(dest<0||imm<0||!tagLike(imm)) continue;
        long rep=dest-0x90, dvt=0;
        for(long back=a-6; back>=a-80; back--){ if(u8(back)==0xC7&&u8(back+1)==0x05&&u32(back+2)==rep){ dvt=u32(back+6); break; } }
        if(vtRange(dvt)) tagDesc.put(tagStr(imm), dvt);
      }
    }

    PrintWriter pw=new PrintWriter(new BufferedWriter(new FileWriter(
      "C:\\Users\\Joe\\Desktop\\Tribes Browser Based\\re\\gui_full_map.txt")));
    TreeSet<Long> distinct=new TreeSet<>();
    // Only GUI-relevant tags: FG* SG* ME* MM* (skip sim-object/event tags)
    pw.println("######## tag -> descVt -> create -> objVtable ########");
    Map<String,Long> tagObj=new LinkedHashMap<>();
    for(Map.Entry<String,Long> en:tagDesc.entrySet()){
      String t=en.getKey(); long dvt=en.getValue();
      char c0=t.charAt(0), c1=t.charAt(1);
      boolean gui = (c0=='F'&&c1=='G')||(c0=='S'&&c1=='G')||(c0=='M'&&c1=='e')||t.equals("MMsb")||(c0=='M'&&c1=='E');
      if(!gui) continue;
      long create=slot(dvt,0);
      long ovt = code(create)? objVtableFromCreate(create) : 0;
      pw.println(String.format("%-5s descVt=%08x create=%08x objVt=%08x", t, dvt, create, ovt));
      if(vtRange(ovt)) tagObj.put(t, ovt);
    }

    pw.println("\n\n######## per-class FULL object vtable (slots 0..44) ########");
    for(Map.Entry<String,Long> en:tagObj.entrySet()){
      long ovt=en.getValue();
      pw.println("\n==== "+en.getKey()+"  objVt=0x"+Long.toHexString(ovt)+" ====");
      for(int i=0;i<44;i++){ long s=slot(ovt,i);
        if(!code(s)){ if(s==0||!vtRange(s)&&!code(s)){} pw.println(String.format("  [%2d] %08x %s",i,s,fname(s))); }
        else { pw.println(String.format("  [%2d] %08x %s",i,s,fname(s))); distinct.add(s); }
      }
    }
    pw.close();

    PrintWriter pd=new PrintWriter(new BufferedWriter(new FileWriter(
      "C:\\Users\\Joe\\Desktop\\Tribes Browser Based\\re\\gui_distinct_fns.txt")));
    pd.println("# distinct GUI vtable functions ("+distinct.size()+")");
    for(long f:distinct) pd.println(String.format("%08x %s", f, fname(f)));
    pd.close();
    println("wrote gui_full_map.txt + gui_distinct_fns.txt ("+distinct.size()+" distinct fns)");
  }
}
