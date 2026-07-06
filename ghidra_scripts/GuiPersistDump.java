// GuiPersistDump — systematic RE of the ENTIRE T1Vista 1.3 GUI persist format.
// Phase 1: locate the persist read/write vtable slot INDEX by finding the known
//   Control::read (0x539098) / ActiveCtrl::read (0x53c900) / Control::write (0x538dfc) /
//   ActiveCtrl::write (0x53c8a4) inside the GUI vtables.
// Phase 2: for every GUI-control vtable, read the read/write slot fn addr (per-class override
//   detection) + the ctor-region owner.
// Phase 3: decompile the DISTINCT set of read/write functions (dedup — inherited ones shared).
// Output: re/gui_persist_dump.txt
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.app.decompiler.*;
import java.io.*;
import java.util.*;

public class GuiPersistDump extends GhidraScript {
  Memory mem; FunctionManager fm; AddressSpace sp; DecompInterface di; PrintWriter pw;

  // name -> primary vtable (from full_catalog.txt)
  String[][] G = {
    {"FearGui::CFGButton","0x0062232c"},{"FearGui::ControlsListCtrl","0x00625e48"},
    {"FearGui::FGArrayCtrl","0x0061f2b4"},{"FearGui::FGBuddyComboBox","0x006254cc"},
    {"FearGui::FGComboBox","0x00625184"},{"FearGui::FGComboList","0x00625cac"},
    {"FearGui::FGCommandPanel","0x00622b30"},{"FearGui::FGControlsComboBox","0x00626148"},
    {"FearGui::FGControlsPopUp","0x00625b60"},{"FearGui::FGFilterComboBox","0x00627e84"},
    {"FearGui::FGHBuySell","0x0062e1c0"},{"FearGui::FGHInventory","0x0062e024"},
    {"FearGui::FGIRCActiveTextFormat","0x0061fcf0"},{"FearGui::FGIRCTopicCtrl","0x00620b48"},
    {"FearGui::FGMenuCtrl","0x006214d8"},{"FearGui::FGMissionComboBox","0x006267b0"},
    {"FearGui::FGPlayerComboBox","0x00626cbc"},{"FearGui::FGServerFilterComboBox","0x00628514"},
    {"FearGui::FGStandardComboBox","0x00625328"},{"FearGui::FGTabMenu","0x00629df4"},
    {"FearGui::FGTextFormat","0x0061fe4c"},{"FearGui::FearGuiDialog","0x00622888"},
    {"FearGui::FearGuiScrollCtrl","0x00625fe4"},{"FearGui::FilterCtrl","0x006279ac"},
    {"FearGui::FilterVarCtrl","0x00627ce8"},{"FearGui::MMShellBorder","0x00621e18"},
    {"FearGui::MissionListCtrl","0x00626614"},{"FearGui::PlayerListCtrl","0x00626b20"},
    {"FearGui::ShapeView","0x006217f8"},{"FearGui::StandardListCtrl","0x006270d8"},
    {"FearGui::TestEdit","0x0061fb80"},
    {"GWDialog","0x0063a6a0"},{"GWTreeList","0x00631b28"},
    {"MEButton","0x00630aa4"},{"MECheck","0x00630520"},{"MEInspectTagList","0x00631054"},
    {"MEPopup","0x00630250"},{"MEPopupBkgnd","0x006307f8"},{"MEPopupButton","0x00630c0c"},
    {"MERadio","0x00630ee8"},{"METextEdit","0x00630688"},{"METextList","0x0063092c"},
    {"SimGui::Canvas","0x0063bc7c"},{"SimGui::ComboPopUp","0x0063e8c4"},
    {"SimGui::HelpCtrl","0x0063c284"},{"SimGui::MatrixCtrl","0x0063e324"},
    {"SimGui::ProgressCtrl","0x0063dba4"},{"SimGui::ScrollContentCtrl","0x0063da78"},
    {"SimGui::Slider","0x0063e760"},{"SimGui::TSControl","0x0063ddf8"},
    {"SimGui::TestButton","0x0063c6f4"},{"SimGui::TestCheck","0x006303b8"},
    {"SimGui::TestRadial","0x00630d7c"},{"SimGui::TextFormat","0x0063bf9c"},
    {"SimGui::TextList","0x0063e490"},{"SimGui::TextWrap","0x0063e608"},
    {"SimGui::TimerCtrl","0x0063df44"},
    // FGSlider final+base known from prior RE
    {"FearGui::FGSlider(final)","0x00629538"},{"FearGui::FGSlider(base)","0x0061f2dc"},
  };
  // Known persist read/write fns (from prior RE) — used to auto-detect slot index per vtable.
  long[] KNOWN_READ  = {0x539098L, 0x53c900L};
  long[] KNOWN_WRITE = {0x538dfcL, 0x53c8a4L};

  long slot(long vt,int i){ try{ return mem.getInt(sp.getAddress(vt+i*4L))&0xffffffffL; }catch(Exception e){ return 0; } }
  boolean in(long v,long[] a){ for(long x:a) if(x==v) return true; return false; }
  boolean code(long v){ return v>=0x401000L && v<0x60e000L; }

  String dc(long va){
    try{ Address pa=sp.getAddress(va); Function f=fm.getFunctionAt(pa);
      if(f==null){ disassemble(pa); f=createFunction(pa,null); if(f==null)f=fm.getFunctionContaining(pa);}
      if(f==null)return "  <no fn>";
      DecompileResults r=di.decompileFunction(f,90,monitor);
      return (r!=null&&r.decompileCompleted())?r.getDecompiledFunction().getC():"  <fail>";
    }catch(Exception e){return "  <exc "+e+">";}
  }

  public void run() throws Exception {
    mem=currentProgram.getMemory(); fm=currentProgram.getFunctionManager();
    sp=currentProgram.getAddressFactory().getDefaultAddressSpace();
    di=new DecompInterface(); di.openProgram(currentProgram);
    pw=new PrintWriter(new BufferedWriter(new FileWriter(
      "C:\\Users\\Joe\\Desktop\\Tribes Browser Based\\re\\gui_persist_dump.txt")));

    // Phase 1+2: find read/write slot per vtable by matching known fns, else report full-scan.
    // Establish canonical slot index from the vtables where a KNOWN read/write appears.
    int readSlot=-1, writeSlot=-1;
    for(String[] g:G){ long vt=Long.decode(g[1]);
      for(int i=0;i<50;i++){ long s=slot(vt,i);
        if(in(s,KNOWN_READ)  && readSlot<0)  readSlot=i;
        if(in(s,KNOWN_WRITE) && writeSlot<0) writeSlot=i; } }
    pw.println("== canonical readSlot="+readSlot+" writeSlot="+writeSlot+" ==\n");

    // Per-class: report read/write fn at those slots (fallback: scan for any KNOWN match).
    TreeMap<Long,String> readFns = new TreeMap<>();
    TreeMap<Long,String> writeFns = new TreeMap<>();
    pw.println("======== PER-CLASS read/write slot fns ========");
    for(String[] g:G){ String nm=g[0]; long vt=Long.decode(g[1]);
      long rf = readSlot>=0? slot(vt,readSlot):0;
      long wf = writeSlot>=0? slot(vt,writeSlot):0;
      // sanity: if slot value isn't code, scan for a known read/write in this vtable
      if(!code(rf)){ for(int i=0;i<50;i++){ long s=slot(vt,i); if(in(s,KNOWN_READ)){rf=s;break;} } }
      if(!code(wf)){ for(int i=0;i<50;i++){ long s=slot(vt,i); if(in(s,KNOWN_WRITE)){wf=s;break;} } }
      pw.println(String.format("%-34s vt=%08x  read=%08x  write=%08x", nm, vt, rf, wf));
      if(code(rf))  readFns.put(rf,  (readFns.containsKey(rf)? readFns.get(rf)+", ":"")+nm);
      if(code(wf)) writeFns.put(wf,(writeFns.containsKey(wf)?writeFns.get(wf)+", ":"")+nm);
    }

    // Phase 3: decompile DISTINCT read fns, then distinct write fns.
    pw.println("\n\n######## DISTINCT READ FUNCTIONS ########");
    for(Map.Entry<Long,String> e:readFns.entrySet()){
      pw.println("\n================ read 0x"+Long.toHexString(e.getKey())+"  ["+e.getValue()+"] ================");
      pw.println(dc(e.getKey()));
    }
    pw.println("\n\n######## DISTINCT WRITE FUNCTIONS ########");
    for(Map.Entry<Long,String> e:writeFns.entrySet()){
      pw.println("\n================ write 0x"+Long.toHexString(e.getKey())+"  ["+e.getValue()+"] ================");
      pw.println(dc(e.getKey()));
    }
    pw.close(); println("wrote re/gui_persist_dump.txt readSlot="+readSlot+" writeSlot="+writeSlot);
  }
}
