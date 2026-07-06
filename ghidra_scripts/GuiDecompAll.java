// GuiDecompAll — decompile EVERY distinct GUI vtable function (from gui_distinct_fns.txt) into one
// organized reference, AND extract+decompile the secondary (Responder/input) vtables for the key
// classes (Control, ActiveCtrl via TestButton, FGSlider, Canvas) so the real onMouse*/onKey*
// handlers are captured. Output: re/gui_all_fns.txt  + re/gui_secondary.txt
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.app.decompiler.*;
import java.io.*;
import java.util.*;

public class GuiDecompAll extends GhidraScript {
  Memory mem; FunctionManager fm; AddressSpace sp; DecompInterface di; Listing lst;
  long u32(long a){ try{ return mem.getInt(sp.getAddress(a))&0xffffffffL; }catch(Exception e){ return -1; } }
  int u8(long a){ try{ return mem.getByte(sp.getAddress(a))&0xff; }catch(Exception e){ return -1; } }
  long slot(long vt,int i){ return u32(vt+i*4L); }
  boolean code(long v){ return v>=0x401000L && v<0x60e000L; }
  boolean vtRange(long v){ return v>=0x610000L && v<0x670000L; }
  String dc(long va){
    try{ Address pa=sp.getAddress(va); Function f=fm.getFunctionAt(pa);
      if(f==null){ disassemble(pa); f=createFunction(pa,null); if(f==null)f=fm.getFunctionContaining(pa);}
      if(f==null)return "  <no fn>";
      DecompileResults r=di.decompileFunction(f,45,monitor);
      return (r!=null&&r.decompileCompleted())?r.getDecompiledFunction().getC():"  <fail>";
    }catch(Exception e){return "  <exc "+e+">";}
  }
  // secondary vtable = the [obj+0x6c] store in the ctor. Scan create (+ 1 call level) for
  // `C7 40 6c <vt>` / `C7 47 6c <vt>` (MOV [reg+0x6c], imm), take last.
  long secondaryFromCreate(long start, int depth){
    long found=0; ArrayList<Long> calls=new ArrayList<>(); long a=start;
    for(int i=0;i<260;i++){ int op=u8(a); if(op<0) break; if(op==0xC3||op==0xC2) break;
      if(op==0xC7){ int modrm=u8(a+1);
        if((modrm&0xC0)==0x40 && (modrm&0x38)==0){ int disp=u8(a+2); long v=u32(a+3);
          if(disp==0x6c && vtRange(v)) found=v; a+=7; continue; }
        if((modrm&0xC0)==0x00 && (modrm&0x38)==0){ a+=6; continue; }
        if((modrm&0xC0)==0x80 && (modrm&0x38)==0){ a+=10; continue; }
      }
      if(op==0xE8){ long t=(a+5+(int)u32(a+1))&0xffffffffL; if(code(t)&&t!=start) calls.add(t); }
      Instruction ins=lst.getInstructionAt(sp.getAddress(a));
      if(ins==null){ try{disassemble(sp.getAddress(a));}catch(Exception e){} ins=lst.getInstructionAt(sp.getAddress(a)); }
      a += (ins!=null)? ins.getLength():1;
    }
    if(found!=0) return found;
    if(depth<3) for(int k=calls.size()-1;k>=0;k--){ long v=secondaryFromCreate(calls.get(k),depth+1); if(v!=0) return v; }
    return 0;
  }
  public void run() throws Exception {
    mem=currentProgram.getMemory(); fm=currentProgram.getFunctionManager();
    sp=currentProgram.getAddressFactory().getDefaultAddressSpace(); lst=currentProgram.getListing();
    di=new DecompInterface(); di.openProgram(currentProgram);

    // ---- secondary (input) vtables for key classes ----
    // class -> create fn (from gui_full_map). Control uses SGct create 0x544324; TestButton 0x543dfc;
    // FGSlider(FGsk) 0x4cb27c; Canvas: find via 'SGcv'? use MainCanvas objVt indirectly.
    String[][] keys={{"Control","0x544324"},{"ActiveCtrl(TestButton)","0x543dfc"},
                     {"FGSlider","0x4cb27c"},{"TestCheck","0x54419c"}};
    PrintWriter ps=new PrintWriter(new BufferedWriter(new FileWriter(
      "C:\\Users\\Joe\\Desktop\\Tribes Browser Based\\re\\gui_secondary.txt")));
    String[] rname={"onMouseDown","onMouseRepeat","onMouseUp","onMouseMove","onMouseEnter","onMouseLeave",
      "onMouseDragged","onRightMouseDown","onRightMouseRepeat","onRightMouseUp","onRightMouseDragged",
      "onKeyUp","onKeyRepeat","onKeyDown","onMessage","loseFirstResponder","becomeFirstResponder"};
    for(String[] k:keys){ long create=Long.decode(k[1]); long sec=secondaryFromCreate(create,0);
      ps.println("\n######## "+k[0]+"  secondary(Responder) vtable = 0x"+Long.toHexString(sec)+" ########");
      if(sec==0){ ps.println(" <not found>"); continue; }
      for(int i=0;i<17;i++){ long s=slot(sec,i);
        ps.println("\n==== ["+i+"] "+rname[i]+"  0x"+Long.toHexString(s)+" ====");
        if(code(s)) ps.println(dc(s)); else ps.println("  (non-code)"); }
    }
    ps.close();

    // ---- decompile every distinct GUI vtable function ----
    BufferedReader br=new BufferedReader(new FileReader(
      "C:\\Users\\Joe\\Desktop\\Tribes Browser Based\\re\\gui_distinct_fns.txt"));
    PrintWriter pw=new PrintWriter(new BufferedWriter(new FileWriter(
      "C:\\Users\\Joe\\Desktop\\Tribes Browser Based\\re\\gui_all_fns.txt")));
    String line; int n=0;
    while((line=br.readLine())!=null){ line=line.trim(); if(line.startsWith("#")||line.isEmpty()) continue;
      String hex=line.split("\\s+")[0]; long a;
      try{ a=Long.decode("0x"+hex); }catch(Exception e){ continue; }
      pw.println("\n================ 0x"+hex+" ================");
      pw.println(dc(a)); n++;
    }
    br.close(); pw.close();
    println("wrote gui_secondary.txt + gui_all_fns.txt ("+n+" fns)");
  }
}
