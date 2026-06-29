// AIJetScan — find the 1.40 analog of T1Vista FUN_0043bf3c's mount-vtable call:
//   CALL dword ptr [reg+0x150]  whose object came from [this+0x1cc] (the AI mount obj,
//   T1Vista +0x1c0 -> 1.40 +0x1cc per the main AI fix). That's the AIJet crash site.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import java.io.*;

public class AIJetScan extends GhidraScript {
  public void run() throws Exception {
    Listing lst=currentProgram.getListing();
    PrintWriter pw=new PrintWriter(new BufferedWriter(new FileWriter(
      System.getProperty("user.home")+"/aijet.txt")));
    InstructionIterator ii=lst.getInstructions(true); int found=0;
    while(ii.hasNext()){
      Instruction ins=ii.next(); String s=ins.toString();
      if(s.startsWith("CALL") && s.contains("[") && s.contains("0x150]")){
        // walk back up to 12 instrs, looking for a [..+0x1cc] load
        Address a=ins.getAddress(); boolean mount=false; StringBuilder ctx=new StringBuilder();
        java.util.List<Instruction> back=new java.util.ArrayList<>();
        Address c=a;
        for(int k=0;k<12;k++){ Instruction p=lst.getInstructionBefore(c); if(p==null) break; back.add(0,p); c=p.getAddress(); }
        for(Instruction p: back){ String ps=p.toString(); if(ps.contains("0x1cc]")) mount=true;
          ctx.append(String.format("      0x%08x  %s%n",p.getAddress().getOffset(),ps)); }
        if(mount){
          Function f=currentProgram.getFunctionManager().getFunctionContaining(a);
          pw.println("\n*** mount-vtable+0x150 call @0x"+Long.toHexString(a.getOffset())+(f!=null?" in "+f.getName()+" @0x"+Long.toHexString(f.getEntryPoint().getOffset()):"")+" ***");
          pw.print(ctx.toString());
          byte[] ib=ins.getBytes(); StringBuilder h=new StringBuilder(); for(byte b:ib) h.append(String.format("%02x ",b&0xff));
          pw.println(String.format("    0x%08x  %-22s %s  <<<< CALL site", a.getOffset(), h.toString(), s));
          // a few instrs after, for the detour back-target
          Address n=a.add(ins.getLength());
          for(int k=0;k<4;k++){ Instruction q=lst.getInstructionAt(n); if(q==null) break;
            pw.println(String.format("      0x%08x  %s",n.getOffset(),q.toString())); n=n.add(q.getLength()); }
          found++;
        }
      }
    }
    pw.println("\nfound "+found+" mount(+0x1cc)-vtable+0x150 call sites");
    pw.close(); println("wrote re/aijet.txt ("+found+" sites)");
  }
}
