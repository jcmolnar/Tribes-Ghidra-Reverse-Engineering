// GuiPersist0 — AUTHORITATIVE re-dump using the PROVEN persist slots: read=slot0, write=slot1
// (from Persistent::readObject FUN_0058b2e0 dispatch (**obj)() and writeObject (*obj+4)()).
// For every GUI control: print slot0/1/10/11 addrs (to expose where slot10 diverges), then
// decompile the DISTINCT slot-0 read fns and slot-1 write fns. Output: re/gui_persist0.txt
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.app.decompiler.*;
import java.io.*;
import java.util.*;

public class GuiPersist0 extends GhidraScript {
  Memory mem; FunctionManager fm; AddressSpace sp; DecompInterface di; PrintWriter pw;
  String[][] G = {
    {"CFGButton","0x0062232c"},{"ControlsListCtrl","0x00625e48"},{"FGArrayCtrl","0x0061f2b4"},
    {"FGBuddyComboBox","0x006254cc"},{"FGComboBox","0x00625184"},{"FGComboList","0x00625cac"},
    {"FGCommandPanel","0x00622b30"},{"FGControlsComboBox","0x00626148"},{"FGControlsPopUp","0x00625b60"},
    {"FGFilterComboBox","0x00627e84"},{"FGHBuySell","0x0062e1c0"},{"FGHInventory","0x0062e024"},
    {"FGIRCActiveTextFormat","0x0061fcf0"},{"FGIRCTopicCtrl","0x00620b48"},{"FGMenuCtrl","0x006214d8"},
    {"FGMissionComboBox","0x006267b0"},{"FGPlayerComboBox","0x00626cbc"},{"FGServerFilterComboBox","0x00628514"},
    {"FGStandardComboBox","0x00625328"},{"FGTabMenu","0x00629df4"},{"FGTextFormat","0x0061fe4c"},
    {"FearGuiDialog","0x00622888"},{"FearGuiScrollCtrl","0x00625fe4"},{"FilterCtrl","0x006279ac"},
    {"FilterVarCtrl","0x00627ce8"},{"MMShellBorder","0x00621e18"},{"MissionListCtrl","0x00626614"},
    {"PlayerListCtrl","0x00626b20"},{"ShapeView","0x006217f8"},{"StandardListCtrl","0x006270d8"},
    {"TestEdit","0x0061fb80"},{"GWDialog","0x0063a6a0"},{"GWTreeList","0x00631b28"},
    {"MEButton","0x00630aa4"},{"MECheck","0x00630520"},{"MEInspectTagList","0x00631054"},
    {"MEPopup","0x00630250"},{"MEPopupBkgnd","0x006307f8"},{"MEPopupButton","0x00630c0c"},
    {"MERadio","0x00630ee8"},{"METextEdit","0x00630688"},{"METextList","0x0063092c"},
    {"SimGui::Canvas","0x0063bc7c"},{"SimGui::ComboPopUp","0x0063e8c4"},{"SimGui::HelpCtrl","0x0063c284"},
    {"SimGui::MatrixCtrl","0x0063e324"},{"SimGui::ProgressCtrl","0x0063dba4"},{"SimGui::ScrollContentCtrl","0x0063da78"},
    {"SimGui::Slider","0x0063e760"},{"SimGui::TSControl","0x0063ddf8"},{"SimGui::TestButton","0x0063c6f4"},
    {"SimGui::TestCheck","0x006303b8"},{"SimGui::TestRadial","0x00630d7c"},{"SimGui::TextFormat","0x0063bf9c"},
    {"SimGui::TextList","0x0063e490"},{"SimGui::TextWrap","0x0063e608"},{"SimGui::TimerCtrl","0x0063df44"},
    {"FGSlider(final)","0x00629538"},{"FGSlider(base)","0x0061f2dc"},{"SimGui::Control?","0x0063bbe0"},
  };
  long slot(long vt,int i){ try{ return mem.getInt(sp.getAddress(vt+i*4L))&0xffffffffL; }catch(Exception e){ return 0; } }
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
      "C:\\Users\\Joe\\Desktop\\Tribes Browser Based\\re\\gui_persist0.txt")));
    TreeMap<Long,String> readFns=new TreeMap<>(), writeFns=new TreeMap<>();
    pw.println(String.format("%-26s %-10s %-9s %-9s | %-9s %-9s","class","vt","read(s0)","write(s1)","s10","s11"));
    for(String[] g:G){ String nm=g[0]; long vt=Long.decode(g[1]);
      long r0=slot(vt,0), w1=slot(vt,1), s10=slot(vt,10), s11=slot(vt,11);
      pw.println(String.format("%-26s %08x  %08x  %08x | %08x %08x", nm, vt, r0, w1, s10, s11));
      if(code(r0)) readFns.put(r0,(readFns.containsKey(r0)?readFns.get(r0)+", ":"")+nm);
      if(code(w1)) writeFns.put(w1,(writeFns.containsKey(w1)?writeFns.get(w1)+", ":"")+nm);
    }
    pw.println("\n\n######## DISTINCT SLOT-0 READ FUNCTIONS (the REAL persist reads) ########");
    for(Map.Entry<Long,String> e:readFns.entrySet()){
      pw.println("\n======== read 0x"+Long.toHexString(e.getKey())+"  ["+e.getValue()+"] ========");
      pw.println(dc(e.getKey())); }
    pw.println("\n\n######## DISTINCT SLOT-1 WRITE FUNCTIONS ########");
    for(Map.Entry<Long,String> e:writeFns.entrySet()){
      pw.println("\n======== write 0x"+Long.toHexString(e.getKey())+"  ["+e.getValue()+"] ========");
      pw.println(dc(e.getKey())); }
    pw.close(); println("wrote re/gui_persist0.txt");
  }
}
