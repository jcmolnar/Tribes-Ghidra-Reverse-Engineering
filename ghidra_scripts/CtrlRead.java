// CtrlRead — decompile the REAL 1.3 SimGui::Control::read (FUN_00539098, reached from
// ActiveCtrl::read FUN_0053c900) plus its parent chain, so we get the exact field byte layout
// (where position/extent/consoleVariable/objectCt actually sit). Output: re/ctrl_read.txt
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.app.decompiler.*;
import java.io.*;

public class CtrlRead extends GhidraScript {
  AddressSpace sp; FunctionManager fm; DecompInterface di; PrintWriter pw;
  void dc(String label, long va){
    pw.println("\n================ "+label+" @0x"+Long.toHexString(va)+" ================");
    try{ Address pa=sp.getAddress(va); Function f=fm.getFunctionAt(pa);
      if(f==null){ disassemble(pa); f=createFunction(pa,null); if(f==null)f=fm.getFunctionContaining(pa);}
      if(f==null){pw.println("  <no fn>");return;}
      DecompileResults r=di.decompileFunction(f,90,monitor);
      pw.println((r!=null&&r.decompileCompleted())?r.getDecompiledFunction().getC():"  <fail>");
    }catch(Exception e){pw.println("  <exc "+e+">");}
  }
  public void run() throws Exception {
    sp=currentProgram.getAddressFactory().getDefaultAddressSpace(); fm=currentProgram.getFunctionManager();
    di=new DecompInterface(); di.openProgram(currentProgram);
    pw=new PrintWriter(new BufferedWriter(new FileWriter(
      "C:\\Users\\Joe\\Desktop\\Tribes Browser Based\\re\\ctrl_read.txt")));
    dc("ActiveCtrl::read (FUN_0053c900)", 0x53c900L);
    dc("Control::read (FUN_00539098)", 0x539098L);
    dc("write chain: ActiveCtrl::write (FUN_0053c8a4)", 0x53c8a4L);
    dc("Control::write? (FUN_00538dfc)", 0x538dfcL);
    pw.close(); println("wrote re/ctrl_read.txt");
  }
}
