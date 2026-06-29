// AnimOverride — locate Player::updateAnimation + the setOverride(1) bot-lock sites in T1Vista.exe.
// Anchors: the "lowerback" string (insertOverride setup), and the setPriority(5000)=0x1388 constant
// (the looks-thread priority in updateAnimation). Find functions referencing these, decompile, and
// dump raw disasm so the setOverride(0/1/2) call sites + their immediate args are visible for patching.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.scalar.*;
import ghidra.program.model.symbol.*;
import ghidra.app.decompiler.*;
import java.io.*;
import java.util.*;

public class AnimOverride extends GhidraScript {
  PrintWriter pw; DecompInterface di; AddressSpace sp; Memory mem;
  String deco(long va){
    Function f=getFunctionContaining(sp.getAddress(va));
    if(f==null){ try{disassemble(sp.getAddress(va)); f=createFunction(sp.getAddress(va),null);}catch(Exception e){} }
    if(f==null) return "  <no fn @0x"+Long.toHexString(va)+">";
    DecompileResults r=di.decompileFunction(f,120,monitor);
    return "FUN_"+Long.toHexString(f.getEntryPoint().getOffset())+" (size "+f.getBody().getNumAddresses()+"):\n"
      +((r!=null&&r.decompileCompleted())?r.getDecompiledFunction().getC():"<fail>");
  }
  void disasm(long va){
    Function f=getFunctionContaining(sp.getAddress(va)); if(f==null) return;
    pw.println("  ---- disasm FUN_"+Long.toHexString(f.getEntryPoint().getOffset())+" ----");
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
          if(ok && (i==0||buf[i-1]==0) ) h.add(b.getStart().getOffset()+i);}
      }catch(Exception e){} }
    return h;
  }
  // functions whose body references the 4-byte LE address of a string, OR contain a scalar == val
  Set<Long> fnsRefAddr(long a){
    Set<Long> s=new LinkedHashSet<Long>();
    MemoryBlock tb=mem.getBlock(".text");
    try{ byte[] buf=new byte[(int)tb.getSize()]; mem.getBytes(tb.getStart(),buf); long base=tb.getStart().getOffset();
      byte b0=(byte)(a&0xff),b1=(byte)((a>>8)&0xff),b2=(byte)((a>>16)&0xff),b3=(byte)((a>>24)&0xff);
      for(int i=0;i+3<buf.length;i++) if(buf[i]==b0&&buf[i+1]==b1&&buf[i+2]==b2&&buf[i+3]==b3){
        Function f=getFunctionContaining(sp.getAddress(base+i)); if(f!=null) s.add(f.getEntryPoint().getOffset()); }
    }catch(Exception e){}
    return s;
  }
  Set<Long> fnsWithScalar(long val){
    Set<Long> s=new LinkedHashSet<Long>();
    InstructionIterator it=currentProgram.getListing().getInstructions(true);
    while(it.hasNext()){ Instruction ins=it.next();
      for(int oi=0;oi<ins.getNumOperands();oi++) for(Object o:ins.getOpObjects(oi))
        if(o instanceof Scalar && ((Scalar)o).getUnsignedValue()==val){
          Function f=getFunctionContaining(ins.getAddress()); if(f!=null) s.add(f.getEntryPoint().getOffset()); }
    }
    return s;
  }
  public void run() throws Exception {
    sp=currentProgram.getAddressFactory().getDefaultAddressSpace(); mem=currentProgram.getMemory();
    di=new DecompInterface(); di.openProgram(currentProgram);
    pw=new PrintWriter(new BufferedWriter(new FileWriter("C:\\Users\\Joe\\Desktop\\Tribes Browser Based\\re\\animoverride.txt")));

    pw.println("===== \"lowerback\" string + referencing functions =====");
    Set<Long> animFns=new LinkedHashSet<Long>();
    for(long h: findStr("lowerback")){
      Set<Long> fns=fnsRefAddr(h);
      pw.println("  str@0x"+Long.toHexString(h)+" refed by "+fns);
      animFns.addAll(fns);
    }
    pw.println("\n===== functions referencing 5000 (0x1388, the looks setPriority) =====");
    Set<Long> prioFns=fnsWithScalar(5000);
    pw.println("  "+prioFns);
    animFns.addAll(prioFns);

    pw.println("\n===== decompile + disasm candidate animation functions =====");
    for(long fn: animFns){
      pw.println("\n################ FUN_"+Long.toHexString(fn)+" ################");
      pw.println(deco(fn));
      disasm(fn);
    }
    pw.close();
    println("wrote re/animoverride.txt; candidates="+animFns);
  }
}
