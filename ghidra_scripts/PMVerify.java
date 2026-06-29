// PMVerify — confirm clientFreeList offset (0x344f8) is the POP source on client-add, and resolve MaxTeams.
//  (1) Find functions that READ *(this + 0x344f8) as a ClientRep and advance via rep->nextClient(+8)^key
//      (the clientAdded "pop a free id" path) — print them.
//  (2) MaxTeams: the team array stride is 0x419c (TeamRep) starting at 0x41fc (findTeam: param_2*0x419c+0x41fc).
//      teamList ends where clientList begins (~0x25104). MaxTeams = (0x25104 - 0x41fc)/0x419c. Compute + print.
//      Also decompile teamAdded (processEvent case 0x44f memcpy of 0x419c) and the team-init to cross-check.
//  (3) Decompile clientAdded by xref to FUN_004b8ec0's sibling / functions reading 0x344f8.
// Writes re/pm_verify.txt.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.scalar.*;
import ghidra.app.decompiler.*;
import java.io.*;
import java.util.*;

public class PMVerify extends GhidraScript {
  Memory mem; AddressSpace sp; FunctionManager fm; SymbolTable st; DecompInterface di; Listing lst;
  long textMin, textMax;
  PrintWriter pw;
  void out(String s){ println(s); pw.println(s); }
  Function funcAt(long ea){ Address a=sp.getAddress(ea); Function f=fm.getFunctionAt(a); if(f==null)f=fm.getFunctionContaining(a); if(f==null){try{disassemble(a);f=createFunction(a,null);}catch(Exception e){}} return f; }
  String deco(long ea){ Function f=funcAt(ea); if(f==null)return "  <no func @0x"+Long.toHexString(ea)+">"; DecompileResults r=di.decompileFunction(f,120,monitor); return (r!=null&&r.decompileCompleted())?r.getDecompiledFunction().getC():"  <fail @0x"+Long.toHexString(ea)+">"; }
  String nm(long ea){ Function f=fm.getFunctionContaining(sp.getAddress(ea)); return f!=null?f.getName(true)+" @"+f.getEntryPoint():"?"; }

  public void run() throws Exception {
    mem=currentProgram.getMemory(); sp=currentProgram.getAddressFactory().getDefaultAddressSpace();
    fm=currentProgram.getFunctionManager(); st=currentProgram.getSymbolTable(); lst=currentProgram.getListing();
    di=new DecompInterface(); di.openProgram(currentProgram);
    MemoryBlock tb=mem.getBlock(".text"); textMin=tb.getStart().getOffset(); textMax=tb.getEnd().getOffset();
    pw=new PrintWriter(new BufferedWriter(new FileWriter(
       System.getProperty("user.home")+"/pm_verify.txt")));

    // MaxTeams arithmetic
    long teamBase=0x41fc, teamStride=0x419c, clientArrayStart=0x25104;
    long maxTeams=(clientArrayStart - teamBase)/teamStride;
    long rem=(clientArrayStart - teamBase)%teamStride;
    out("=== MaxTeams from array geometry ===");
    out(String.format("  teamList base=0x%x stride=sizeof(TeamRep)=0x%x  clientArray start~0x%x",teamBase,teamStride,clientArrayStart));
    out(String.format("  MaxTeams = (0x%x - 0x%x)/0x%x = %d  (remainder 0x%x)",clientArrayStart,teamBase,teamStride,maxTeams,rem));

    // find instructions referencing the immediate 0x344f8 (clientFreeList) — POP/read sites
    out("\n=== instructions referencing 0x344f8 (clientFreeList member) ===");
    long FREE=0x344f8L;
    LinkedHashSet<Function> hits=new LinkedHashSet<Function>();
    InstructionIterator ii=lst.getInstructions(true);
    while(ii.hasNext()){
      Instruction in=ii.next();
      for(int op=0; op<in.getNumOperands(); op++){
        for(Object o: in.getOpObjects(op)){
          if(o instanceof Scalar && ((Scalar)o).getUnsignedValue()==FREE){
            Function f=fm.getFunctionContaining(in.getAddress());
            out("  "+in.getAddress()+"  "+in+"   in "+(f!=null?f.getName(true)+"@"+f.getEntryPoint():"?"));
            if(f!=null) hits.add(f);
          }
        }
      }
    }
    out("  distinct functions touching 0x344f8: "+hits.size());
    int c=0;
    for(Function f: hits){
      if(c++>=8) break;
      out("\n---- "+f.getName(true)+" @"+f.getEntryPoint()+" ----");
      out(deco(f.getEntryPoint().getOffset()));
      monitor.checkCancelled();
    }

    pw.close();
    println("MaxTeams="+maxTeams+" (rem 0x"+Long.toHexString(rem)+")  freelist-touching fns="+hits.size()+" -> re/pm_verify.txt");
  }
}
