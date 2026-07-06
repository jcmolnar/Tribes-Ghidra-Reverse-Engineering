// SliderDeep — resolve the FGSlider persist read contradiction with RAW DISASSEMBLY.
// (1) Dump both FGSlider vtables (0x629538 final, 0x61f2dc base) slots 0..24 w/ names.
// (2) Raw-disassemble the read region 0x539d50..0x539e80 and the write 0x53c7f8..0x53c8a4.
// (3) Decompile the field helpers FUN_006070c8 (read) and FUN_00510724 (write) and the
//     slider sub-helpers FUN_00539dd0/FUN_00539dfc/FUN_00539884, and SimGroup::read 0x4ff5f0.
// Output: re/slider_deep.txt
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.app.decompiler.*;
import java.io.*;

public class SliderDeep extends GhidraScript {
  Memory mem; FunctionManager fm; AddressSpace sp; DecompInterface di; PrintWriter pw; Listing lst;

  String dc(long va){
    try{ Address pa=sp.getAddress(va); Function f=fm.getFunctionAt(pa);
      if(f==null){ disassemble(pa); f=createFunction(pa,null); if(f==null)f=fm.getFunctionContaining(pa);}
      if(f==null)return "  <no fn>";
      DecompileResults r=di.decompileFunction(f,90,monitor);
      return (r!=null&&r.decompileCompleted())?r.getDecompiledFunction().getC():"  <fail>";
    }catch(Exception e){return "  <exc "+e+">";}
  }
  void disasm(long start,long end){
    Address a=sp.getAddress(start);
    while(a.getOffset()<end){
      Instruction ins=lst.getInstructionAt(a);
      if(ins==null){ try{ disassemble(a);}catch(Exception e){} ins=lst.getInstructionAt(a); }
      if(ins==null){ pw.println(String.format("  %08x  <no insn>",a.getOffset())); a=a.add(1); continue; }
      pw.println(String.format("  %08x  %s", a.getOffset(), ins.toString()));
      a=a.add(ins.getLength());
    }
  }
  void vt(long base){
    pw.println("\n---- vtable 0x"+Long.toHexString(base)+" ----");
    for(int i=0;i<24;i++){
      long s; try{ s=mem.getInt(sp.getAddress(base+i*4L))&0xffffffffL; }catch(Exception e){break;}
      Function f=fm.getFunctionAt(sp.getAddress(s));
      pw.println(String.format("  slot[%2d] = %08x  %s", i, s, f!=null?f.getName():""));
    }
  }
  public void run() throws Exception {
    mem=currentProgram.getMemory(); fm=currentProgram.getFunctionManager();
    sp=currentProgram.getAddressFactory().getDefaultAddressSpace(); lst=currentProgram.getListing();
    di=new DecompInterface(); di.openProgram(currentProgram);
    pw=new PrintWriter(new BufferedWriter(new FileWriter(
      "C:\\Users\\Joe\\Desktop\\Tribes Browser Based\\re\\slider_deep.txt")));

    pw.println("######## FGSlider vtables ########");
    vt(0x629538L); vt(0x61f2dcL);

    pw.println("\n\n######## RAW DISASM: FGSlider read 0x539d50..0x539e80 ########");
    disasm(0x539d50L,0x539e80L);
    pw.println("\n######## RAW DISASM: FGSlider write 0x53c7f8..0x53c8a4 ########");
    disasm(0x53c7f8L,0x53c8a4L);

    long[] more = {0x539dd0L,0x539dfcL,0x539884L, 0x6070c8L,0x510724L, 0x4ff5f0L,0x4ff598L,0x54aeb4L,0x54ae10L};
    String[] nm = {"FUN_00539dd0 slider read helper A","FUN_00539dfc slider read helper B",
      "FUN_00539884 slider write parent","FUN_006070c8 field-read helper","FUN_00510724 field-write helper",
      "FUN_004ff5f0 SimGroup::read (children)","FUN_004ff598 SimGroup::write",
      "FUN_0054aeb4 MatrixCtrl parent read","FUN_0054ae10 MatrixCtrl parent write"};
    pw.println("\n\n######## HELPERS ########");
    for(int i=0;i<more.length;i++){
      pw.println("\n================ "+nm[i]+" @0x"+Long.toHexString(more[i])+" ================");
      pw.println(dc(more[i]));
    }
    pw.close(); println("wrote re/slider_deep.txt");
  }
}
