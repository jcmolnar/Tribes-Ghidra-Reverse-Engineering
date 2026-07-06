// PbaFrames — crack the FGSlider .pba frame-index -> bitmap-field mapping. The render (FUN_004c9c70)
// draws from stored GFXBitmap* fields 0x1cc/0x1d0/0x1d4/0x2e4/0x2e8/0x2ec/0x2f0/0x2f4. Those are set
// in onAdd from bma->getBitmap(FRAME). Find the FGSlider onAdd (slot 13 of FGsk objVt 0x629824),
// raw-disassemble it + FUN_004ca08c, and surface every `getBitmap(index)` -> `MOV [this+off], eax`
// so we learn which .pba frame is arrow/thumb/track. Output: re/pba_frames.txt
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.app.decompiler.*;
import java.io.*;

public class PbaFrames extends GhidraScript {
  Memory mem; FunctionManager fm; AddressSpace sp; Listing lst; DecompInterface di;
  long slot(long vt,int i){ try{ return mem.getInt(sp.getAddress(vt+i*4L))&0xffffffffL; }catch(Exception e){ return 0; } }
  boolean code(long v){ return v>=0x401000L && v<0x60e000L; }
  String dc(long va){
    try{ Address pa=sp.getAddress(va); Function f=fm.getFunctionAt(pa);
      if(f==null){ disassemble(pa); f=createFunction(pa,null); if(f==null)f=fm.getFunctionContaining(pa);}
      if(f==null)return "  <no fn>";
      DecompileResults r=di.decompileFunction(f,120,monitor);
      return (r!=null&&r.decompileCompleted())?r.getDecompiledFunction().getC():"  <fail>";
    }catch(Exception e){return "  <exc "+e+">";}
  }
  void disasm(PrintWriter pw,long start,long end){
    Address a=sp.getAddress(start);
    while(a.getOffset()<end){
      Instruction ins=lst.getInstructionAt(a);
      if(ins==null){ try{ disassemble(a);}catch(Exception e){} ins=lst.getInstructionAt(a); }
      if(ins==null){ int bb=0; try{ bb=mem.getByte(a)&0xff; }catch(Exception e){} pw.println(String.format("  %08x  <db %02x>",a.getOffset(),bb)); a=a.add(1); continue; }
      pw.println(String.format("  %08x  %s", a.getOffset(), ins.toString()));
      a=a.add(ins.getLength());
    }
  }
  public void run() throws Exception {
    mem=currentProgram.getMemory(); fm=currentProgram.getFunctionManager();
    sp=currentProgram.getAddressFactory().getDefaultAddressSpace(); lst=currentProgram.getListing();
    di=new DecompInterface(); di.openProgram(currentProgram);
    PrintWriter pw=new PrintWriter(new BufferedWriter(new FileWriter(
      "C:\\Users\\Joe\\Desktop\\Tribes Browser Based\\re\\pba_frames.txt")));
    long onAdd = slot(0x629824L,13);       // FGsk real onAdd = 0x4ca0f0
    long onRender = slot(0x629824L,30);    // FGsk real onRender = 0x4ca7b8
    long onPre = slot(0x629824L,31);
    pw.println("FGsk objVt=0x629824  onAdd=0x"+Long.toHexString(onAdd)+"  onRender=0x"+Long.toHexString(onRender)+"  onPreRender=0x"+Long.toHexString(onPre));
    pw.println("\n######## onAdd (0x4ca0f0) decompile ########");
    pw.println(dc(onAdd));
    pw.println("\n######## onAdd raw disasm (frame-index -> field) ########");
    disasm(pw,onAdd,onAdd+0x600);
    pw.println("\n\n######## onRender (0x4ca7b8) decompile ########");
    pw.println(dc(onRender));
    pw.println("\n######## onPreRender ("+Long.toHexString(onPre)+") decompile ########");
    pw.println(dc(onPre));
    pw.close(); println("wrote re/pba_frames.txt");
  }
}
