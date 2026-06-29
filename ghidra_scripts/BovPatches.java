// BovPatches — dump T1Vista patch-site context (orig bytes + decompile) and the
// ServerSidePlugin AIJet handler, to port Bov's remaining AI patches to 1.40.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.app.decompiler.*;
import java.io.*;

public class BovPatches extends GhidraScript {
  String hex(byte[] b){ StringBuilder s=new StringBuilder(); for(byte x:b) s.append(String.format("%02x ",x&0xff)); return s.toString(); }
  public void run() throws Exception {
    String name=currentProgram.getName().toLowerCase();
    long[] addrs;
    if(name.contains("t1vista")) addrs=new long[]{0x40de38L,0x40de80L};
    else if(name.contains("serverside")) addrs=new long[]{0x1000883aL,0x10004866L};
    else { println("skip "+name); return; }
    AddressSpace sp=currentProgram.getAddressFactory().getDefaultAddressSpace();
    Listing lst=currentProgram.getListing();
    DecompInterface di=new DecompInterface(); di.openProgram(currentProgram);
    PrintWriter pw=new PrintWriter(new BufferedWriter(new FileWriter(
      "C:\\Users\\Joe\\Desktop\\Tribes Browser Based\\re\\bov_"+(name.contains("t1vista")?"t1vista":"plugin")+".txt")));
    for(long va:addrs){
      Address a=sp.getAddress(va);
      Function f=currentProgram.getFunctionManager().getFunctionContaining(a);
      pw.println("================ patch site 0x"+Long.toHexString(va)+(f!=null?"  in "+f.getName()+" @0x"+Long.toHexString(f.getEntryPoint().getOffset()):"")+" ================");
      // raw bytes at the site
      try{ byte[] bb=new byte[8]; currentProgram.getMemory().getBytes(a,bb); pw.println("  orig bytes @site: "+hex(bb)); }catch(Exception e){}
      // disasm window around the site (walk from function start, print within +-0x20)
      if(f!=null){
        Address cur=f.getEntryPoint();
        for(int i=0;i<800;i++){
          Instruction ins=lst.getInstructionAt(cur);
          if(ins==null) break;
          long off=cur.getOffset();
          if(off>=va-0x20 && off<=va+0x18){
            String mark = (off==va)?"  <<<< PATCH SITE":"";
            byte[] ib=ins.getBytes();
            pw.println(String.format("    0x%08x  %-28s %-34s%s", off, hex(ib), ins.toString(), mark));
          }
          cur=cur.add(ins.getLength());
          if(!f.getBody().contains(cur)) break;
        }
        DecompileResults r=di.decompileFunction(f,60,monitor);
        if(r!=null&&r.decompileCompleted()){
          pw.println("  --- decompile "+f.getName()+" ---");
          String[] ls=r.getDecompiledFunction().getC().split("\n");
          for(int i=0;i<Math.min(ls.length,70);i++) pw.println("  "+ls[i]);
        }
      }
      pw.println();
    }
    pw.close();
    println("wrote re/bov_*.txt for "+name);
  }
}
