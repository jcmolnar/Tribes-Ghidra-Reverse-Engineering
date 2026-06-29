// GLFind — locate the engine's OpenGL upload path in T1Vista. The engine loads GL via glLoader
// (GetProcAddress -> a global "GLV" pointer table), so find: the GL function-name strings, the
// functions that reference them (glLoader init, which reveals the global slot each is stored to),
// and callers of glTexImage2D/glBindTexture/glTexSubImage2D so we can hook the engine-side upload.
// Output: re/glupload.txt
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.*;
import ghidra.app.decompiler.*;
import java.io.*;
import java.util.*;

public class GLFind extends GhidraScript {
  PrintWriter pw; DecompInterface di; AddressSpace sp; Memory mem; FunctionManager fm;
  String decomp(long va){
    Function f=fm.getFunctionContaining(sp.getAddress(va));
    if(f==null){ try{disassemble(sp.getAddress(va)); f=createFunction(sp.getAddress(va),null);}catch(Exception e){} }
    if(f==null) return "  <no fn @0x"+Long.toHexString(va)+">";
    DecompileResults r=di.decompileFunction(f,90,monitor);
    return "FUN_"+Long.toHexString(f.getEntryPoint().getOffset())+":\n"
      +((r!=null&&r.decompileCompleted())?r.getDecompiledFunction().getC():"<fail>");
  }
  List<Long> findStr(String s){
    List<Long> h=new ArrayList<Long>(); byte[] pat=(s+"\0").getBytes();
    for(MemoryBlock b:mem.getBlocks()){ if(!b.isInitialized())continue;
      try{ byte[] buf=new byte[(int)b.getSize()]; mem.getBytes(b.getStart(),buf);
        for(int i=0;i+pat.length<buf.length;i++){boolean ok=true;
          for(int j=0;j<pat.length;j++) if(buf[i+j]!=pat[j]){ok=false;break;}
          if(ok && (i==0||buf[i-1]==0)) h.add(b.getStart().getOffset()+i);}
      }catch(Exception e){} }
    return h;
  }
  Set<Long> fnsRefAddr(long a){
    Set<Long> s=new LinkedHashSet<Long>();
    for(MemoryBlock tb:mem.getBlocks()){ if(!tb.isInitialized())continue;
      try{ byte[] buf=new byte[(int)tb.getSize()]; mem.getBytes(tb.getStart(),buf); long base=tb.getStart().getOffset();
        byte b0=(byte)(a&0xff),b1=(byte)((a>>8)&0xff),b2=(byte)((a>>16)&0xff),b3=(byte)((a>>24)&0xff);
        for(int i=0;i+3<buf.length;i++) if(buf[i]==b0&&buf[i+1]==b1&&buf[i+2]==b2&&buf[i+3]==b3){
          Function f=fm.getFunctionContaining(sp.getAddress(base+i)); if(f!=null) s.add(f.getEntryPoint().getOffset()); }
      }catch(Exception e){} }
    return s;
  }
  public void run() throws Exception {
    sp=currentProgram.getAddressFactory().getDefaultAddressSpace(); mem=currentProgram.getMemory();
    fm=currentProgram.getFunctionManager();
    di=new DecompInterface(); di.openProgram(currentProgram);
    pw=new PrintWriter(new BufferedWriter(new FileWriter(System.getProperty("user.home")+"/glupload.txt")));
    String[] names={"glTexImage2D","glTexSubImage2D","glBindTexture","glGenTextures","glDeleteTextures","glTexParameteri"};
    Set<Long> loaders=new LinkedHashSet<Long>();
    for(String n:names){
      for(long h:findStr(n)){
        Set<Long> fns=fnsRefAddr(h);
        pw.println("\""+n+"\" @0x"+Long.toHexString(h)+" refed by "+fns);
        loaders.addAll(fns);
      }
    }
    pw.println("\n############ functions referencing the GL name strings (glLoader init etc) ############");
    for(long fn:loaders){
      pw.println("\n################ FUN_"+Long.toHexString(fn)+" ################");
      pw.println(decomp(fn));
    }
    pw.close();
    println("wrote re/glupload.txt; loaders="+loaders);
  }
}
