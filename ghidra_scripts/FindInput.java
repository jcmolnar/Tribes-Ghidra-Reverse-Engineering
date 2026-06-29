// FindInput — locate the DirectInput mouse SetCooperativeLevel call in Tribes 1.40.655.
// Find DirectInput*Create imports, decompile their callers (the input init), AND decompile the
// SimInputDevice vtable methods (vtable @0x6671fc) to find SetCooperativeLevel + the DISCL flags
// so we can patch EXCLUSIVE->NONEXCLUSIVE. Output: re/input_re.txt
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.mem.*;
import ghidra.app.decompiler.*;
import java.io.*;
import java.util.*;

public class FindInput extends GhidraScript {
  DecompInterface di; FunctionManager fm; SymbolTable st; PrintWriter pw; Memory mem; AddressSpace sp;
  Set<Long> done=new HashSet<Long>();
  long u32(long va) throws Exception { return mem.getInt(sp.getAddress(va)) & 0xffffffffL; }
  void deco(Function f, String why){
    if(f==null) return; long k=f.getEntryPoint().getOffset(); if(!done.add(k)) return;
    pw.println("\n======== "+f.getName(true)+" @0x"+Long.toHexString(k)+"  ["+why+"] ========");
    DecompileResults r=di.decompileFunction(f,60,monitor);
    pw.println((r!=null&&r.decompileCompleted())? r.getDecompiledFunction().getC():"  <fail>");
  }
  public void run() throws Exception {
    di=new DecompInterface(); di.openProgram(currentProgram);
    fm=currentProgram.getFunctionManager(); st=currentProgram.getSymbolTable();
    mem=currentProgram.getMemory(); sp=currentProgram.getAddressFactory().getDefaultAddressSpace();
    pw=new PrintWriter(new BufferedWriter(new FileWriter(System.getProperty("user.home")+"/input_re.txt")));

    // 1) DirectInput imports + callers
    pw.println("##### DirectInput import callers #####");
    SymbolIterator it=st.getAllSymbols(true);
    List<Symbol> dinput=new ArrayList<Symbol>();
    while(it.hasNext()){ Symbol s=it.next(); String n=s.getName();
      if(n.toLowerCase().contains("directinput")||n.equals("DirectInputCreateA")||n.equals("DirectInput8Create")) dinput.add(s); }
    ReferenceManager rm=currentProgram.getReferenceManager();
    for(Symbol s: dinput){
      pw.println("  import: "+s.getName(true)+" @0x"+Long.toHexString(s.getAddress().getOffset()));
      ReferenceIterator ri=rm.getReferencesTo(s.getAddress());
      while(ri.hasNext()){ Reference r=ri.next(); Function f=fm.getFunctionContaining(r.getFromAddress());
        if(f!=null) deco(f,"calls "+s.getName()); }
    }

    // 2) SimInputDevice vtable methods (find capture/SetCooperativeLevel)
    long vt=0x6671fcL;  // SimInputDevice::vftable
    pw.println("\n##### SimInputDevice vtable @0x"+Long.toHexString(vt)+" methods #####");
    for(int i=0;i<32;i++){
      long fa; try{ fa=u32(vt+i*4L);}catch(Exception e){break;}
      Function f=fm.getFunctionAt(sp.getAddress(fa));
      if(f!=null){ pw.println("  [slot "+i+"] 0x"+Long.toHexString(fa)+" "+f.getName()); }
    }
    // decompile all distinct SimInputDevice vtable methods
    for(int i=0;i<32;i++){ long fa; try{fa=u32(vt+i*4L);}catch(Exception e){break;}
      Function f=fm.getFunctionAt(sp.getAddress(fa)); if(f!=null) deco(f,"SimInputDevice vtbl slot "+i); }

    pw.close(); println("wrote re/input_re.txt (dinput callers="+dinput.size()+")");
  }
}
