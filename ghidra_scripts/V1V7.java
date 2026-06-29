// V1V7 — locate DataBlockEvent::unpack (V1 createDataBlock NULL) + ScoreListCtrl::onPreRender (V7 tabStops OOB).
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.app.decompiler.*;
import java.io.*;
import java.util.*;

public class V1V7 extends GhidraScript {
  PrintWriter pw;
  DecompInterface di;
  AddressSpace sp;

  String deco(long va) {
    Function f = getFunctionContaining(sp.getAddress(va));
    if (f == null) return "  <no fn @0x"+Long.toHexString(va)+">";
    DecompileResults r = di.decompileFunction(f, 60, monitor);
    return (r!=null && r.decompileCompleted()) ? r.getDecompiledFunction().getC() : "  <decompile fail>";
  }

  void disasmRange(long start, long end) {
    Listing lst = currentProgram.getListing();
    InstructionIterator it = lst.getInstructions(sp.getAddress(start), true);
    while (it.hasNext()) {
      Instruction ins = it.next();
      if (ins.getAddress().getOffset() > end) break;
      StringBuilder b = new StringBuilder();
      for (byte x : safeBytes(ins)) b.append(String.format("%02x ", x & 0xff));
      pw.println(String.format("    0x%08x  %-22s %s", ins.getAddress().getOffset(), b.toString().trim(), ins.toString()));
    }
  }
  byte[] safeBytes(Instruction ins){ try{return ins.getBytes();}catch(Exception e){return new byte[0];} }

  public void run() throws Exception {
    sp = currentProgram.getAddressFactory().getDefaultAddressSpace();
    di = new DecompInterface(); di.openProgram(currentProgram);
    pw = new PrintWriter(new BufferedWriter(new FileWriter(
        "C:\\Users\\Joe\\Desktop\\Tribes Browser Based\\re\\v1v7.txt")));

    // ---- find BS_readInt ----
    Symbol ri = null;
    for (Symbol s : currentProgram.getSymbolTable().getSymbols("BS_readInt")) { ri = s; break; }
    if (ri == null) { pw.println("BS_readInt symbol NOT FOUND"); pw.close(); return; }
    long riAddr = ri.getAddress().getOffset();
    pw.println("BS_readInt @ 0x"+Long.toHexString(riAddr));

    // ---- (A) V1: scan call sites to BS_readInt, recover width from preceding MOV EDX,imm ----
    // group call sites by containing function; report functions whose width sequence contains 6,8,8.
    ReferenceManager rm = currentProgram.getReferenceManager();
    Map<Long,List<int[]>> perFn = new LinkedHashMap<Long,List<int[]>>(); // fnAddr -> list of {callVA, width}
    ReferenceIterator refs = rm.getReferencesTo(ri.getAddress());
    Listing lst = currentProgram.getListing();
    while (refs.hasNext()) {
      Reference r = refs.next();
      if (r.getReferenceType() != RefType.UNCONDITIONAL_CALL && !r.getReferenceType().isCall()) continue;
      Address callAt = r.getFromAddress();
      Function f = getFunctionContaining(callAt);
      if (f == null) continue;
      // look back up to 6 instructions for MOV EDX, imm  (Borland fastcall: width in EDX)
      int width = -1;
      Instruction cur = lst.getInstructionAt(callAt);
      Instruction p = cur;
      for (int i=0;i<6 && p!=null;i++){
        p = p.getPrevious();
        if (p==null) break;
        String t = p.toString();
        if (t.startsWith("MOV EDX,0x")) { try{ width=(int)Long.parseLong(t.substring(10),16);}catch(Exception e){} break; }
        if (t.startsWith("MOV EDX,") ) { try{ width=Integer.parseInt(t.substring(8));}catch(Exception e){} break; }
        if (t.startsWith("PUSH 0x")) { try{ width=(int)Long.parseLong(t.substring(7),16);}catch(Exception e){} break; }
      }
      long fa = f.getEntryPoint().getOffset();
      if (!perFn.containsKey(fa)) perFn.put(fa, new ArrayList<int[]>());
      perFn.get(fa).add(new int[]{(int)callAt.getOffset(), width});
    }
    pw.println("\n===== (V1) functions calling BS_readInt with a 6 then 8 then 8 sequence =====");
    long dbeUnpack = 0;
    for (Map.Entry<Long,List<int[]>> e : perFn.entrySet()) {
      List<int[]> cs = e.getValue();
      // build width sequence
      StringBuilder seq = new StringBuilder();
      boolean has688=false;
      for (int i=0;i<cs.size();i++){ seq.append(cs.get(i)[1]).append(" "); }
      // detect 6,8,8 anywhere
      for (int i=0;i+2<cs.size();i++){
        if (cs.get(i)[1]==6 && cs.get(i+1)[1]==8 && cs.get(i+2)[1]==8){ has688=true; break; }
      }
      if (has688) {
        pw.println(String.format("  *** FUN_%08x  widths=[%s]", e.getKey(), seq.toString().trim()));
        dbeUnpack = e.getKey();
      }
    }

    if (dbeUnpack != 0) {
      pw.println("\n===== (V1) DataBlockEvent::unpack candidate FUN_"+String.format("%08x",dbeUnpack)+" =====");
      pw.println("---- decompile ----");
      pw.println(deco(dbeUnpack));
      pw.println("---- full disasm ----");
      Function f = getFunctionContaining(sp.getAddress(dbeUnpack));
      disasmRange(f.getEntryPoint().getOffset(), f.getBody().getMaxAddress().getOffset());
    } else {
      pw.println("  (no 6,8,8 function found — dumping ALL fns that read width 6)");
      for (Map.Entry<Long,List<int[]>> e : perFn.entrySet()){
        for (int[] c : e.getValue()) if (c[1]==6){ pw.println(String.format("  FUN_%08x reads width 6 @0x%08x", e.getKey(), c[0])); break; }
      }
    }

    // ---- (B) V7: decompile + disasm FUN_00489d00 (writes 0x280 as a value = tabStops[stop]=640) ----
    pw.println("\n\n===== (V7) ScoreListCtrl::onPreRender candidate FUN_00489d00 =====");
    pw.println("---- decompile ----");
    pw.println(deco(0x489d00L));
    pw.println("---- full disasm ----");
    Function sf = getFunctionContaining(sp.getAddress(0x489d00L));
    if (sf != null) disasmRange(sf.getEntryPoint().getOffset(), sf.getBody().getMaxAddress().getOffset());
    else pw.println("  <no fn @0x489d00>");

    pw.close();
    println("wrote re/v1v7.txt; dbeUnpack=0x"+Long.toHexString(dbeUnpack));
  }
}
