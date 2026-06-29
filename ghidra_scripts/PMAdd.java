// PMAdd — decompile the server client/bot add+drop path to confirm the id-recycle/cross-wire root cause.
// clientAdded = FUN_0040b788 (mem-mapped); find clientDropped/removeClient via the "dropped"/"added" strings;
// decompile getFreeId (returns free-list head id). Output re/pmadd.txt.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.app.decompiler.*;
import java.io.*;
import java.util.*;

public class PMAdd extends GhidraScript {
  PrintWriter pw; DecompInterface di; AddressSpace sp; Memory mem;
  String deco(long va){
    Function f=getFunctionContaining(sp.getAddress(va));
    if(f==null){ try{disassemble(sp.getAddress(va)); f=createFunction(sp.getAddress(va),null);}catch(Exception e){} }
    if(f==null) return "  <no fn @0x"+Long.toHexString(va)+">";
    DecompileResults r=di.decompileFunction(f,120,monitor);
    return "FUN_"+Long.toHexString(f.getEntryPoint().getOffset())+":\n"+((r!=null&&r.decompileCompleted())?r.getDecompiledFunction().getC():"<fail>");
  }
  List<Long> findStr(String s){
    List<Long> h=new ArrayList<Long>(); byte[] pat=s.getBytes();
    for(MemoryBlock b:mem.getBlocks()){ if(!b.isInitialized())continue;
      try{ byte[] buf=new byte[(int)b.getSize()]; mem.getBytes(b.getStart(),buf);
        for(int i=0;i+pat.length<buf.length;i++){boolean ok=true;
          for(int j=0;j<pat.length;j++) if(buf[i+j]!=pat[j]){ok=false;break;}
          if(ok) h.add(b.getStart().getOffset()+i);}
      }catch(Exception e){}
    }
    return h;
  }
  Set<Long> funcsRef(long a){
    Set<Long> s=new LinkedHashSet<Long>();
    // scan .text for the 4-byte LE constant referencing the string
    MemoryBlock tb=mem.getBlock(".text");
    try{ byte[] buf=new byte[(int)tb.getSize()]; mem.getBytes(tb.getStart(),buf);
      byte b0=(byte)(a&0xff),b1=(byte)((a>>8)&0xff),b2=(byte)((a>>16)&0xff),b3=(byte)((a>>24)&0xff);
      long base=tb.getStart().getOffset();
      for(int i=0;i+3<buf.length;i++) if(buf[i]==b0&&buf[i+1]==b1&&buf[i+2]==b2&&buf[i+3]==b3){
        Function f=getFunctionContaining(sp.getAddress(base+i)); if(f!=null) s.add(f.getEntryPoint().getOffset());
      }
    }catch(Exception e){}
    return s;
  }
  public void run() throws Exception {
    sp=currentProgram.getAddressFactory().getDefaultAddressSpace(); mem=currentProgram.getMemory();
    di=new DecompInterface(); di.openProgram(currentProgram);
    pw=new PrintWriter(new BufferedWriter(new FileWriter("C:\\Users\\Joe\\Desktop\\Tribes Browser Based\\re\\pmadd.txt")));

    pw.println("==================== clientAdded = FUN_0040b788 ====================");
    pw.println(deco(0x40b788L));

    // find clientDropped/removeClient via the dropped + added system messages
    for(String s : new String[]{"dropped - id","added - id"}){
      pw.println("\n==================== string \""+s+"\" ====================");
      for(long h: findStr(s)){
        Set<Long> fns=funcsRef(h);
        pw.println("  str@0x"+Long.toHexString(h)+" refed by "+fns);
        for(long fn: fns){ pw.println(deco(fn)); }
      }
    }
    pw.close();
    println("wrote re/pmadd.txt");
  }
}
