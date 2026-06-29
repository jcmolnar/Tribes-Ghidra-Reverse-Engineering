// ArmCtrl — find what controls the ARM nodes (larm/rarm) vs the lowerback torso override.
// 1) locate node-name strings + the override-setup function (insertOverride). 2) re-dump
// Player::updateAnimation FUN_004108dc looking for ANY other override-byte writes / setPriority
// (CALL 0x5bd9a0) beyond the lowerback +0x9e one. 3) decompile setup + the larm-referencing fns.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.*;
import ghidra.app.decompiler.*;
import java.io.*;
import java.util.*;

public class ArmCtrl extends GhidraScript {
  PrintWriter pw; DecompInterface di; AddressSpace sp; Memory mem;
  String deco(long va){ Function f=getFunctionContaining(sp.getAddress(va));
    if(f==null) return "  <no fn @0x"+Long.toHexString(va)+">";
    DecompileResults r=di.decompileFunction(f,120,monitor);
    return "FUN_"+Long.toHexString(f.getEntryPoint().getOffset())+":\n"+((r!=null&&r.decompileCompleted())?r.getDecompiledFunction().getC():"<fail>"); }
  List<Long> findStr(String s){ List<Long> h=new ArrayList<Long>(); byte[] pat=s.getBytes();
    for(MemoryBlock b:mem.getBlocks()){ if(!b.isInitialized())continue;
      try{ byte[] buf=new byte[(int)b.getSize()]; mem.getBytes(b.getStart(),buf);
        for(int i=0;i+pat.length<buf.length;i++){boolean ok=true; for(int j=0;j<pat.length;j++) if(buf[i+j]!=pat[j]){ok=false;break;}
          if(ok && (i==0||buf[i-1]==0) && buf[i+pat.length]==0) h.add(b.getStart().getOffset()+i);} }catch(Exception e){} }
    return h; }
  Set<Long> refFns(long a){ Set<Long> s=new LinkedHashSet<Long>();
    ReferenceIterator it=currentProgram.getReferenceManager().getReferencesTo(sp.getAddress(a));
    while(it.hasNext()){ Function f=getFunctionContaining(it.next().getFromAddress()); if(f!=null) s.add(f.getEntryPoint().getOffset()); }
    // byte-scan fallback
    MemoryBlock tb=mem.getBlock(".text");
    try{ byte[] buf=new byte[(int)tb.getSize()]; mem.getBytes(tb.getStart(),buf); long base=tb.getStart().getOffset();
      byte b0=(byte)(a&0xff),b1=(byte)((a>>8)&0xff),b2=(byte)((a>>16)&0xff),b3=(byte)((a>>24)&0xff);
      for(int i=0;i+3<buf.length;i++) if(buf[i]==b0&&buf[i+1]==b1&&buf[i+2]==b2&&buf[i+3]==b3){ Function f=getFunctionContaining(sp.getAddress(base+i)); if(f!=null) s.add(f.getEntryPoint().getOffset()); } }catch(Exception e){}
    return s; }
  public void run() throws Exception {
    sp=currentProgram.getAddressFactory().getDefaultAddressSpace(); mem=currentProgram.getMemory();
    di=new DecompInterface(); di.openProgram(currentProgram);
    pw=new PrintWriter(new BufferedWriter(new FileWriter("C:\\Users\\Joe\\Desktop\\Tribes Browser Based\\re\\armctrl.txt")));

    pw.println("===== node-name strings + referencing functions =====");
    Set<Long> setupFns=new LinkedHashSet<Long>();
    for(String n: new String[]{"lowerback","larm","rarm","head","rhand","lhand"}){
      for(long h: findStr(n)){ Set<Long> fns=refFns(h); pw.println("  \""+n+"\" @0x"+Long.toHexString(h)+" refed by "+fns); setupFns.addAll(fns); }
    }

    pw.println("\n===== updateAnimation FUN_004108dc: ALL byte-imm writes to shape fields + setPriority(0x5bd9a0) calls =====");
    Function ua=getFunctionAt(sp.getAddress(0x4108dcL));
    if(ua!=null){ InstructionIterator it=currentProgram.getListing().getInstructions(ua.getBody(),true);
      while(it.hasNext()){ Instruction ins=it.next(); String t=ins.toString();
        boolean byteWrite = t.startsWith("MOV byte ptr") && t.contains(",0x");
        boolean prioCall = false;
        for(Reference r:ins.getReferencesFrom()) if(r.getReferenceType().isCall() && r.getToAddress().getOffset()==0x5bd9a0L) prioCall=true;
        if(byteWrite||prioCall){ StringBuilder b=new StringBuilder();
          try{for(byte x:ins.getBytes())b.append(String.format("%02x ",x&0xff));}catch(Exception e){}
          pw.println(String.format("  0x%08x  %-22s %s %s", ins.getAddress().getOffset(), b.toString().trim(), t, prioCall?"  <-- setPriority":"")); }
      } }

    pw.println("\n===== decompile node-setup / larm-referencing functions =====");
    for(long fn: setupFns){ pw.println("\n######## "+deco(fn)); }
    pw.close();
    println("wrote re/armctrl.txt; setupFns="+setupFns);
  }
}
