// DropPath — BINARY ground truth for the client/AI drop+reuse path in T1Vista.exe.
// Anchor clientDropped/clientAdded via the script-call format strings (asserts are stripped in release).
// Force-disassemble vtable-only methods. Also enumerate the PlayerManager cluster around FUN_0040b788.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.*;
import ghidra.app.decompiler.*;
import java.io.*;
import java.util.*;

public class DropPath extends GhidraScript {
  PrintWriter pw; DecompInterface di; AddressSpace sp; Memory mem;

  Function ensureFn(long va){
    Function f=getFunctionContaining(sp.getAddress(va));
    if(f!=null) return f;
    // scan back up to 0x500 bytes for a plausible Borland prologue and create the fn
    for(long a=va; a>va-0x500; a--){
      try{
        int b0=mem.getByte(sp.getAddress(a))&0xff;
        int b1=mem.getByte(sp.getAddress(a+1))&0xff;
        int b2=mem.getByte(sp.getAddress(a+2))&0xff;
        boolean pro = (b0==0x55 && b1==0x8b && b2==0xec)       // PUSH EBP; MOV EBP,ESP
                   || (b0==0x53 && b1==0x8b && b2==0xc8)       // (varies)
                   || (b0==0x53 && b1==0x56 && b2==0x57);      // PUSH EBX;ESI;EDI
        if(pro){
          // ensure previous byte is a RET/INT3/NOP (function boundary) to reduce false starts
          int pv=mem.getByte(sp.getAddress(a-1))&0xff;
          if(pv==0xc3||pv==0xcc||pv==0x90||((pv&0xf8)==0xc0 /*ret n*/)|| pv==0xc2){
            try{ disassemble(sp.getAddress(a)); Function nf=createFunction(sp.getAddress(a),null); if(nf!=null) return nf; }catch(Exception e){}
          }
        }
      }catch(Exception e){}
    }
    try{ disassemble(sp.getAddress(va)); }catch(Exception e){}
    return getFunctionContaining(sp.getAddress(va));
  }
  String deco(Function f){
    if(f==null) return "<no fn>";
    DecompileResults r=di.decompileFunction(f,120,monitor);
    return "FUN_"+Long.toHexString(f.getEntryPoint().getOffset())+":\n"+((r!=null&&r.decompileCompleted())?r.getDecompiledFunction().getC():"<fail>");
  }
  void disasm(Function f){
    if(f==null) return;
    InstructionIterator it=currentProgram.getListing().getInstructions(f.getBody(),true);
    while(it.hasNext()){ Instruction ins=it.next(); StringBuilder b=new StringBuilder();
      try{for(byte x:ins.getBytes())b.append(String.format("%02x ",x&0xff));}catch(Exception e){}
      pw.println(String.format("    0x%08x  %-20s %s",ins.getAddress().getOffset(),b.toString().trim(),ins.toString())); }
  }
  List<Long> findStr(String s){
    List<Long> h=new ArrayList<Long>(); byte[] pat=s.getBytes();
    for(MemoryBlock b:mem.getBlocks()){ if(!b.isInitialized())continue;
      try{ byte[] buf=new byte[(int)b.getSize()]; mem.getBytes(b.getStart(),buf);
        for(int i=0;i+pat.length<buf.length;i++){boolean ok=true;
          for(int j=0;j<pat.length;j++) if(buf[i+j]!=pat[j]){ok=false;break;}
          if(ok) h.add(b.getStart().getOffset()+i);}
      }catch(Exception e){} }
    return h;
  }
  List<Long> refSites(long a){
    List<Long> sites=new ArrayList<Long>();
    ReferenceIterator it=currentProgram.getReferenceManager().getReferencesTo(sp.getAddress(a));
    while(it.hasNext()) sites.add(it.next().getFromAddress().getOffset());
    MemoryBlock tb=mem.getBlock(".text");
    try{ byte[] buf=new byte[(int)tb.getSize()]; mem.getBytes(tb.getStart(),buf); long base=tb.getStart().getOffset();
      byte b0=(byte)(a&0xff),b1=(byte)((a>>8)&0xff),b2=(byte)((a>>16)&0xff),b3=(byte)((a>>24)&0xff);
      for(int i=0;i+3<buf.length;i++) if(buf[i]==b0&&buf[i+1]==b1&&buf[i+2]==b2&&buf[i+3]==b3) sites.add(base+i);
    }catch(Exception e){}
    return sites;
  }
  void anchor(String label,String str){
    pw.println("\n================= "+label+"  (str \""+str+"\") =================");
    for(long h: findStr(str)){
      List<Long> sites=refSites(h);
      pw.println("  str@0x"+Long.toHexString(h)+"  refsites="+sites.size());
      Set<Long> done=new HashSet<Long>();
      for(long site: sites){
        Function f=ensureFn(site);
        if(f==null){ pw.println("   ref@0x"+Long.toHexString(site)+" (no fn)"); continue; }
        if(!done.add(f.getEntryPoint().getOffset())) continue;
        pw.println("   ref@0x"+Long.toHexString(site)+" in:");
        pw.println(deco(f)); pw.println("   ---- disasm ----"); disasm(f);
      }
    }
  }
  public void run() throws Exception {
    sp=currentProgram.getAddressFactory().getDefaultAddressSpace(); mem=currentProgram.getMemory();
    di=new DecompInterface(); di.openProgram(currentProgram);
    pw=new PrintWriter(new BufferedWriter(new FileWriter(System.getProperty("user.home")+"/droppath.txt")));

    anchor("clientDropped","onClientDisconnect");
    anchor("clientAdded(confirm)","onClientConnect");

    // enumerate PlayerManager cluster to locate removeClient etc.
    pw.println("\n================= functions in [0x40b000,0x40e000] =================");
    FunctionIterator fit=currentProgram.getFunctionManager().getFunctions(sp.getAddress(0x40b000L),true);
    while(fit.hasNext()){ Function f=fit.next(); long a=f.getEntryPoint().getOffset(); if(a>=0x40e000L)break;
      pw.println(String.format("  FUN_%08x size=%d", a, f.getBody().getNumAddresses())); }
    pw.close();
    println("wrote re/droppath.txt");
  }
}
