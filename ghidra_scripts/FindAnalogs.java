// FindAnalogs — locate 1.40 analogs of Bov's behavior/tuning patch sites:
//  (1) PacketRate clamp: "PacketRate" string xref -> clamp fn (CMP/MOV 0x1e to raise to 0x7f)
//  (2) getClientById variants: scan for "sub/add reg,0x800 ... 0x7f" client-lookup pattern
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import java.io.*;
import java.util.*;

public class FindAnalogs extends GhidraScript {
  public void run() throws Exception {
    Listing lst=currentProgram.getListing();
    FunctionManager fm=currentProgram.getFunctionManager();
    ReferenceManager rm=currentProgram.getReferenceManager();
    PrintWriter pw=new PrintWriter(new BufferedWriter(new FileWriter(
      System.getProperty("user.home")+"/analogs.txt")));

    // (1) strings containing "Packet*" + xref functions
    pw.println("===== (1) PacketRate/PacketSize/PacketFrame string sites =====");
    Set<Function> clampFns=new LinkedHashSet<>();
    DataIterator dit=lst.getDefinedData(true);
    while(dit.hasNext()){
      Data d=dit.next(); Object v=d.getValue();
      if(!(v instanceof String)) continue; String s=(String)v;
      if(s.contains("PacketRate")||s.contains("PacketSize")||s.contains("PacketFrame")){
        pw.println("  str @0x"+Long.toHexString(d.getAddress().getOffset())+" = \""+s+"\"");
        ReferenceIterator it=rm.getReferencesTo(d.getAddress());
        while(it.hasNext()){ Reference r=it.next(); Function f=fm.getFunctionContaining(r.getFromAddress());
          if(f!=null){ clampFns.add(f); pw.println("     xref 0x"+Long.toHexString(r.getFromAddress().getOffset())+" in "+f.getName()+" @0x"+Long.toHexString(f.getEntryPoint().getOffset())); } }
      }
    }
    for(Function f: clampFns){
      pw.println("\n  --- "+f.getName()+" @0x"+Long.toHexString(f.getEntryPoint().getOffset())+": clamp instrs (imm 0x1e/0xa/0xc8/0x60) ---");
      Address cur=f.getEntryPoint();
      for(int i=0;i<700;i++){ Instruction ins=lst.getInstructionAt(cur); if(ins==null) break;
        String s=ins.toString();
        if((s.startsWith("CMP")||s.startsWith("MOV")||s.startsWith("PUSH"))&&(s.contains("0x1e")||s.contains("0x1f")||s.endsWith(",0xa")||s.contains("0xc8")||s.contains("0x1c2")||s.contains("0x1c3")||s.contains("0x60"))){
          byte[] ib=ins.getBytes(); StringBuilder h=new StringBuilder(); for(byte b:ib) h.append(String.format("%02x ",b&0xff));
          pw.println(String.format("    0x%08x  %-24s %s", cur.getOffset(), h.toString(), s));
        }
        cur=cur.add(ins.getLength()); if(!f.getBody().contains(cur)) break;
      }
    }

    // (2) getClientById pattern: SUB/ADD reg,0x800 then a 0x7f bound within 6 instrs
    pw.println("\n===== (2) getClientById-like sites (imm 0x800 then 0x7f nearby) =====");
    InstructionIterator ii=lst.getInstructions(true);
    int found=0;
    while(ii.hasNext() && found<40){
      Instruction ins=ii.next(); String s=ins.toString();
      if((s.startsWith("SUB")||s.startsWith("ADD"))&&(s.contains("0x800")||s.contains("0xfffff800"))){
        Address c=ins.getAddress().add(ins.getLength()); boolean hit=false; StringBuilder ctx=new StringBuilder();
        for(int k=0;k<7;k++){ Instruction n=lst.getInstructionAt(c); if(n==null) break;
          ctx.append(String.format("      0x%08x  %s%n",c.getOffset(),n.toString()));
          if(n.toString().contains("0x7f")) hit=true; c=c.add(n.getLength()); }
        if(hit){ Function f=fm.getFunctionContaining(ins.getAddress());
          pw.println("  @0x"+Long.toHexString(ins.getAddress().getOffset())+(f!=null?" in "+f.getName():"")+"  "+s);
          pw.print(ctx.toString()); found++; }
      }
    }
    pw.close(); println("wrote re/analogs.txt");
  }
}
