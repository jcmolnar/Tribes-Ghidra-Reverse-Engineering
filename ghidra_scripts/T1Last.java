// T1Last — locate the last 2 client vectors:
//  V1 createDataBlock: decompile preloadServerDataBlocks (FUN_004227c4) to find the factory call.
//  V7 FearGuiScoreList tabStops: find functions writing imm 0x280 (640 = last tab stop) into an array.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.app.decompiler.*;
import java.io.*;

public class T1Last extends GhidraScript {
  public void run() throws Exception {
    AddressSpace sp=currentProgram.getAddressFactory().getDefaultAddressSpace();
    Listing lst=currentProgram.getListing();
    DecompInterface di=new DecompInterface(); di.openProgram(currentProgram);
    PrintWriter pw=new PrintWriter(new BufferedWriter(new FileWriter(
      "C:\\Users\\Joe\\Desktop\\Tribes Browser Based\\re\\t1last.txt")));

    pw.println("===== V1: preloadServerDataBlocks FUN_004227c4 (find createDataBlock) =====");
    Function pf=currentProgram.getFunctionManager().getFunctionContaining(sp.getAddress(0x4227c4L));
    if(pf!=null){ DecompileResults r=di.decompileFunction(pf,60,monitor);
      if(r!=null&&r.decompileCompleted()) pw.println(r.getDecompiledFunction().getC()); }

    pw.println("\n===== V7: functions with MOV/CMP imm 0x280 (640, tab-stop sentinel) =====");
    int n=0;
    for(Function f: currentProgram.getFunctionManager().getFunctions(true)){
      long sz=f.getBody().getNumAddresses(); if(sz<60||sz>2500) continue;
      Address cur=f.getEntryPoint(); boolean hit=false;
      java.util.List<String> ctx=new java.util.ArrayList<>();
      for(int i=0;i<900;i++){ Instruction ins=lst.getInstructionAt(cur); if(ins==null) break; String s=ins.toString();
        if(s.contains("0x280")&&(s.startsWith("MOV")||s.startsWith("CMP")||s.startsWith("PUSH"))){ hit=true;
          ctx.add(String.format("    0x%08x  %s",cur.getOffset(),s)); }
        cur=cur.add(ins.getLength()); if(!f.getBody().contains(cur)) break; }
      if(hit&&n<12){ pw.println("  "+f.getName()+" @0x"+Long.toHexString(f.getEntryPoint().getOffset())+" (size "+sz+")");
        for(String c:ctx) pw.println(c); n++; }
    }
    pw.close(); println("wrote re/t1last.txt");
  }
}
