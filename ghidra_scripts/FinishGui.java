// FinishGui — close the last gaps: (1) FGsl real read (rep 0x6a6864, descVt 0x628ce4 slot6),
// (2) FGSlider onRender FUN_004c9c70 (.pba frame->field draw order), (3) SimGui SGtk/SGsl descriptor
// slot layout to confirm SG read slot, (4) FGSlider onAdd FUN_004b36e4 already have — but also the
// draw helper it calls. Output: re/finish_gui.txt
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.app.decompiler.*;
import java.io.*;

public class FinishGui extends GhidraScript {
  Memory mem; FunctionManager fm; AddressSpace sp; DecompInterface di; PrintWriter pw;
  long slot(long vt,int i){ try{ return mem.getInt(sp.getAddress(vt+i*4L))&0xffffffffL; }catch(Exception e){ return 0; } }
  boolean code(long v){ return v>=0x401000L && v<0x60e000L; }
  String dc(long va){
    try{ Address pa=sp.getAddress(va); Function f=fm.getFunctionAt(pa);
      if(f==null){ disassemble(pa); f=createFunction(pa,null); if(f==null)f=fm.getFunctionContaining(pa);}
      if(f==null)return "  <no fn>";
      DecompileResults r=di.decompileFunction(f,90,monitor);
      return (r!=null&&r.decompileCompleted())?r.getDecompiledFunction().getC():"  <fail>";
    }catch(Exception e){return "  <exc "+e+">";}
  }
  void vt(String nm,long base,int n){
    pw.println("\n---- descriptor "+nm+" 0x"+Long.toHexString(base)+" ----");
    for(int i=0;i<n;i++){ long s=slot(base,i); Function f=code(s)?fm.getFunctionAt(sp.getAddress(s)):null;
      pw.println(String.format("  slot[%2d]=%08x %s",i,s,f!=null?f.getName():"")); }
  }
  public void run() throws Exception {
    mem=currentProgram.getMemory(); fm=currentProgram.getFunctionManager();
    sp=currentProgram.getAddressFactory().getDefaultAddressSpace();
    di=new DecompInterface(); di.openProgram(currentProgram);
    pw=new PrintWriter(new BufferedWriter(new FileWriter(
      "C:\\Users\\Joe\\Desktop\\Tribes Browser Based\\re\\finish_gui.txt")));
    // (1) FGsl descriptor
    vt("FGsl 0x628ce4",0x628ce4L,12);
    pw.println("\n==== FGsl read (descriptor slot6) 0x"+Long.toHexString(slot(0x628ce4L,6))+" ====");
    pw.println(dc(slot(0x628ce4L,6)));
    // (3) SG descriptor confirm (SGsl 0x63d7bc, SGtk 0x63d87c)
    vt("SGsl 0x63d7bc",0x63d7bcL,12);
    vt("SGtk 0x63d87c",0x63d87cL,12);
    // (2) FGSlider onRender + draw helper
    pw.println("\n\n==== FGSlider onRender FUN_004c9c70 ====");
    pw.println(dc(0x4c9c70L));
    pw.close(); println("wrote re/finish_gui.txt");
  }
}
