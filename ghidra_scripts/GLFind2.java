// GLFind2 — find the engine's GL loader + GLV pointer table. The GL name strings are stored in a
// .data names[] array consumed by a GetProcAddress loop that fills a parallel GLV[] of fn pointers.
// (1) dump the .data neighborhood around the glTexImage2D string-address to see the names[] table;
// (2) find code referencing "opengl32"/"wglGetProcAddress"/"wglMakeCurrent" (the loader) + decompile;
// (3) report the data slot holding the glTexImage2D string ptr so we can locate the parallel GLV slot.
// Output: re/glupload.txt
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.app.decompiler.*;
import java.io.*;
import java.util.*;

public class GLFind2 extends GhidraScript {
  PrintWriter pw; DecompInterface di; AddressSpace sp; Memory mem; FunctionManager fm;
  String decomp(long va){
    Function f=fm.getFunctionContaining(sp.getAddress(va));
    if(f==null){ try{disassemble(sp.getAddress(va)); f=createFunction(sp.getAddress(va),null);}catch(Exception e){} }
    if(f==null) return "  <no fn @0x"+Long.toHexString(va)+">";
    DecompileResults r=di.decompileFunction(f,120,monitor);
    return "FUN_"+Long.toHexString(f.getEntryPoint().getOffset())+":\n"
      +((r!=null&&r.decompileCompleted())?r.getDecompiledFunction().getC():"<fail>");
  }
  long findStr(String s){
    byte[] pat=(s+"\0").getBytes();
    for(MemoryBlock b:mem.getBlocks()){ if(!b.isInitialized())continue;
      try{ byte[] buf=new byte[(int)b.getSize()]; mem.getBytes(b.getStart(),buf);
        for(int i=0;i+pat.length<buf.length;i++){boolean ok=true;
          for(int j=0;j<pat.length;j++) if(buf[i+j]!=pat[j]){ok=false;break;}
          if(ok && (i==0||buf[i-1]==0)) return b.getStart().getOffset()+i;}
      }catch(Exception e){} }
    return 0;
  }
  // all addresses (any block) whose 4 LE bytes == a
  List<Long> refsTo(long a){
    List<Long> out=new ArrayList<Long>();
    for(MemoryBlock tb:mem.getBlocks()){ if(!tb.isInitialized())continue;
      try{ byte[] buf=new byte[(int)tb.getSize()]; mem.getBytes(tb.getStart(),buf); long base=tb.getStart().getOffset();
        byte b0=(byte)(a&0xff),b1=(byte)((a>>8)&0xff),b2=(byte)((a>>16)&0xff),b3=(byte)((a>>24)&0xff);
        for(int i=0;i+3<buf.length;i++) if(buf[i]==b0&&buf[i+1]==b1&&buf[i+2]==b2&&buf[i+3]==b3) out.add(base+i);
      }catch(Exception e){} }
    return out;
  }
  public void run() throws Exception {
    sp=currentProgram.getAddressFactory().getDefaultAddressSpace(); mem=currentProgram.getMemory();
    fm=currentProgram.getFunctionManager();
    di=new DecompInterface(); di.openProgram(currentProgram);
    pw=new PrintWriter(new BufferedWriter(new FileWriter(System.getProperty("user.home")+"/glupload.txt")));

    long sImg = findStr("glTexImage2D");
    pw.println("glTexImage2D string @0x"+Long.toHexString(sImg));
    List<Long> dslots = refsTo(sImg);
    pw.println("string-address appears at: ");
    for(long d:dslots) pw.println("  0x"+Long.toHexString(d)+(fm.getFunctionContaining(sp.getAddress(d))!=null?" (in code)":" (data)"));

    // dump the names[] table neighborhood (the data slot and +-16 pointers)
    for(long d:dslots){
      if(fm.getFunctionContaining(sp.getAddress(d))!=null) continue; // only data
      pw.println("\n---- names[] around 0x"+Long.toHexString(d)+" (each = ptr to a GL name string) ----");
      for(int k=-6;k<=10;k++){
        long slot=d+k*4; int v; try{v=mem.getInt(sp.getAddress(slot));}catch(Exception e){continue;}
        long pv=v&0xffffffffL; StringBuilder nm=new StringBuilder();
        try{ for(int j=0;j<24;j++){ byte c=mem.getByte(sp.getAddress(pv+j)); if(c==0)break; nm.append((char)c);} }catch(Exception e){}
        pw.println(String.format("  [%+d] 0x%08x -> 0x%08x  %s",k,slot,pv,nm.toString()));
      }
    }

    pw.println("\n############ GL loader functions (ref opengl32 / wgl) ############");
    Set<Long> loaders=new LinkedHashSet<Long>();
    for(String n:new String[]{"opengl32.dll","opengl32","wglGetProcAddress","wglMakeCurrent","wglCreateContext"}){
      long s=findStr(n); if(s==0) continue;
      for(long r:refsTo(s)){ Function f=fm.getFunctionContaining(sp.getAddress(r)); if(f!=null) loaders.add(f.getEntryPoint().getOffset()); }
    }
    pw.println("loaders="+loaders);
    for(long fn:loaders){ pw.println("\n################ FUN_"+Long.toHexString(fn)+" ################"); pw.println(decomp(fn)); }
    pw.close();
    println("wrote re/glupload.txt; dslots="+dslots+" loaders="+loaders);
  }
}
