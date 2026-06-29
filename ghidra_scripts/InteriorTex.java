// InteriorTex — locate the interior render -> texture-bind path in T1Vista.exe for an
// animated-texture plugin DLL. Strategy:
//  (1) dump the InteriorShape vtable (0x0061de58) and decompile each slot so we can
//      identify RenderImage (the per-frame interior render entry).
//  (2) find interior source-file assert strings (itrrender/itrgeometry/itrcache/g_bitmap)
//      and list the functions that reference them.
//  (3) decompile a small set of follow functions (the render + texture-cache choke points)
//      with raw disasm so the texture-set call site + its immediate args are visible.
// Output: re/interiortex.txt
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.app.decompiler.*;
import java.io.*;
import java.util.*;

public class InteriorTex extends GhidraScript {
  PrintWriter pw; DecompInterface di; AddressSpace sp; Memory mem; FunctionManager fm;
  long textMin = 0x00401000L, textMax = 0x0060e000L;

  String decomp(long va){
    Function f=fm.getFunctionContaining(sp.getAddress(va));
    if(f==null){ try{disassemble(sp.getAddress(va)); f=createFunction(sp.getAddress(va),null);}catch(Exception e){} }
    if(f==null) return "  <no fn @0x"+Long.toHexString(va)+">";
    DecompileResults r=di.decompileFunction(f,90,monitor);
    return "FUN_"+Long.toHexString(f.getEntryPoint().getOffset())+" (size "+f.getBody().getNumAddresses()+"):\n"
      +((r!=null&&r.decompileCompleted())?r.getDecompiledFunction().getC():"<decompile fail>");
  }
  void disasm(long va){
    Function f=fm.getFunctionContaining(sp.getAddress(va)); if(f==null) return;
    pw.println("  ---- disasm FUN_"+Long.toHexString(f.getEntryPoint().getOffset())+" ----");
    InstructionIterator it=currentProgram.getListing().getInstructions(f.getBody(),true);
    while(it.hasNext()){ Instruction ins=it.next(); StringBuilder b=new StringBuilder();
      try{for(byte x:ins.getBytes())b.append(String.format("%02x ",x&0xff));}catch(Exception e){}
      pw.println(String.format("    0x%08x  %-22s %s",ins.getAddress().getOffset(),b.toString().trim(),ins.toString())); }
  }
  List<Long> findStr(String s){
    List<Long> h=new ArrayList<Long>(); byte[] pat=s.getBytes();
    for(MemoryBlock b:mem.getBlocks()){ if(!b.isInitialized())continue;
      try{ byte[] buf=new byte[(int)b.getSize()]; mem.getBytes(b.getStart(),buf);
        for(int i=0;i+pat.length<buf.length;i++){boolean ok=true;
          for(int j=0;j<pat.length;j++) if(buf[i+j]!=pat[j]){ok=false;break;}
          if(ok) h.add(b.getStart().getOffset()+i);}
      }catch(Exception e){} }
    return h;
  }
  Set<Long> fnsRefAddr(long a){
    Set<Long> s=new LinkedHashSet<Long>();
    for(MemoryBlock tb:mem.getBlocks()){
      if(!tb.isInitialized()) continue;
      try{ byte[] buf=new byte[(int)tb.getSize()]; mem.getBytes(tb.getStart(),buf); long base=tb.getStart().getOffset();
        byte b0=(byte)(a&0xff),b1=(byte)((a>>8)&0xff),b2=(byte)((a>>16)&0xff),b3=(byte)((a>>24)&0xff);
        for(int i=0;i+3<buf.length;i++) if(buf[i]==b0&&buf[i+1]==b1&&buf[i+2]==b2&&buf[i+3]==b3){
          Function f=fm.getFunctionContaining(sp.getAddress(base+i)); if(f!=null) s.add(f.getEntryPoint().getOffset()); }
      }catch(Exception e){}
    }
    return s;
  }
  public void run() throws Exception {
    sp=currentProgram.getAddressFactory().getDefaultAddressSpace(); mem=currentProgram.getMemory();
    fm=currentProgram.getFunctionManager();
    di=new DecompInterface(); di.openProgram(currentProgram);
    pw=new PrintWriter(new BufferedWriter(new FileWriter(System.getProperty("user.home")+"/interiortex.txt")));

    pw.println("############ InteriorShape vtable @0x0061de58 ############");
    Address vt=sp.getAddress(0x0061de58L);
    for(int i=0;i<24;i++){
      Address slotA=vt.add(i*4L); int val;
      try{ val=mem.getInt(slotA);}catch(Exception e){break;}
      long v=val&0xffffffffL;
      if(v<textMin||v>=textMax){ pw.println(String.format("slot[%2d] = 0x%08x  (not .text -> end)",i,v)); break; }
      Function f=fm.getFunctionAt(sp.getAddress(v));
      if(f==null){ try{disassemble(sp.getAddress(v)); f=createFunction(sp.getAddress(v),null);}catch(Exception e){} }
      pw.println(String.format("slot[%2d] = 0x%08x  %s",i,v,(f!=null?f.getName():"?")));
    }

    // decompile the slots most likely to be RenderImage (SimObject RenderImage is usually mid-vtable).
    // We dump slots 2..12 decompiled so RenderImage is visible.
    pw.println("\n############ vtable slot decompiles (find RenderImage) ############");
    for(int i=2;i<14;i++){
      Address slotA=vt.add(i*4L); int val;
      try{ val=mem.getInt(slotA);}catch(Exception e){break;}
      long v=val&0xffffffffL; if(v<textMin||v>=textMax) break;
      pw.println("\n======== slot["+i+"] @0x"+Long.toHexString(v)+" ========");
      pw.println(decomp(v));
    }

    pw.println("\n############ interior/bitmap assert strings + referencing fns ############");
    String[] anchors={"itrrender","itrgeometry","itrcache","itrmaterial","g_bitmap.cpp","Interior\\code"};
    Set<Long> follow=new LinkedHashSet<Long>();
    for(String a:anchors){
      for(long h:findStr(a)){
        Set<Long> fns=fnsRefAddr(h);
        pw.println("  \""+a+"\" @0x"+Long.toHexString(h)+" refed by "+fns);
        follow.addAll(fns);
      }
    }
    pw.println("\n############ decompile + disasm referencing fns ############");
    for(long fn:follow){
      pw.println("\n################ FUN_"+Long.toHexString(fn)+" ################");
      pw.println(decomp(fn));
      disasm(fn);
    }
    pw.close();
    println("wrote re/interiortex.txt; follow="+follow);
  }
}
