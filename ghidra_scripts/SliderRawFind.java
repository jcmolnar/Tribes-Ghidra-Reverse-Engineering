// SliderRawFind — the code referencing the "setDiscretePositions" string (0x6297cf) was never
// disassembled, so scalar/xref scans missed it. Scan raw .text memory for the 4-byte LE address
// (CF 97 62 00), force-disassemble + createFunction around each hit (that's FGSlider::onAdd), find
// which vtable contains that function (FGSlider primary vtable), then disassemble the whole vtable's
// read/write cluster. Output: re/slider_raw.txt
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import java.io.*;
import java.util.*;

public class SliderRawFind extends GhidraScript {
  Memory mem; FunctionManager fm; AddressSpace sp; Listing lst; PrintWriter pw;

  void disasmRange(long ep, int max) {
    Address a = sp.getAddress(ep);
    Function f = fm.getFunctionContaining(a);
    long fe = f != null ? f.getEntryPoint().getOffset() : ep;
    pw.println("\n---- fn @0x" + Long.toHexString(fe) + " " + (f!=null?f.getName():"") + " ----");
    Address x = sp.getAddress(fe);
    Address end = f != null ? f.getBody().getMaxAddress() : sp.getAddress(fe + max*6);
    int n=0;
    while (x != null && x.compareTo(end) <= 0 && n < max) {
      Instruction ins = lst.getInstructionAt(x);
      if (ins == null) { try{ disassemble(x); ins = lst.getInstructionAt(x);}catch(Exception e){} if(ins==null){ x=x.add(1); continue; } }
      pw.println(String.format("  0x%08x  %s", x.getOffset(), ins.toString()));
      x = ins.getAddress().add(ins.getLength()); n++;
    }
  }

  public void run() throws Exception {
    mem=currentProgram.getMemory(); fm=currentProgram.getFunctionManager();
    sp=currentProgram.getAddressFactory().getDefaultAddressSpace(); lst=currentProgram.getListing();
    pw=new PrintWriter(new BufferedWriter(new FileWriter(
      "C:\\Users\\Joe\\Desktop\\Tribes Browser Based\\re\\slider_raw.txt")));

    // target string address (little-endian bytes CF 97 62 00)
    byte[] pat = new byte[]{ (byte)0xCF, (byte)0x97, (byte)0x62, (byte)0x00 };
    long tMin=0x00401000L, tMax=0x0060e000L;
    ArrayList<Long> hits = new ArrayList<Long>();
    Address a = sp.getAddress(tMin);
    Address hi = sp.getAddress(tMax);
    while (a != null && a.compareTo(hi) < 0) {
      Address found = mem.findBytes(a, hi, pat, null, true, monitor);
      if (found == null) break;
      hits.add(found.getOffset());
      a = found.add(1);
      if (hits.size() > 40) break;
    }
    pw.println("#### byte-pattern hits for string-addr 0x6297cf: " + hits.size());
    HashSet<Long> fns = new HashSet<Long>();
    for (Long h : hits) {
      pw.println("   ref @0x" + Long.toHexString(h));
      // force-disassemble a bit before the ref (the PUSH imm sits at h-1)
      try { disassemble(sp.getAddress(h-1)); } catch(Exception e){}
      Function f = fm.getFunctionContaining(sp.getAddress(h-1));
      if (f == null) { try { f = createFunction(sp.getAddress(h-1), null); } catch(Exception e){} }
      if (f == null) {
        // walk back to find a function start
        for (int back=1; back<0x400; back++){ Function g=fm.getFunctionContaining(sp.getAddress(h-back)); if(g!=null){f=g;break;} }
      }
      if (f != null) fns.add(f.getEntryPoint().getOffset());
    }
    pw.println("\n#### onAdd candidate fns: " + fns.size());
    for (Long fa : fns) { pw.println("   0x"+Long.toHexString(fa)); disasmRange(fa, 200); }

    // find vtables containing any onAdd fn -> FGSlider primary vtable
    pw.println("\n\n#### vtables containing an onAdd fn ####");
    for (long vt=0x00620000L; vt<0x00670000L; vt+=4) {
      try {
        int slot=-1;
        for (int i=0;i<45;i++){ long v=mem.getInt(sp.getAddress(vt+i*4L))&0xffffffffL; if(fns.contains(v)){slot=i;break;} }
        if (slot>=0) {
          pw.println("\n**** FGSlider PRIMARY vtable 0x"+Long.toHexString(vt)+"  onAdd@slot["+slot+"] ****");
          for (int j=0;j<45;j++){
            long s=mem.getInt(sp.getAddress(vt+j*4L))&0xffffffffL;
            if(s<0x401000L||s>=0x60e000L){pw.println("  slot["+j+"]=0x"+Long.toHexString(s)+" (end)");break;}
            Function f=fm.getFunctionAt(sp.getAddress(s));
            pw.println(String.format("  slot[%2d]=0x%08x %s",j,s,f!=null?f.getName():""));
          }
          // disasm the low slots (persist read/write cluster) + all slots to be safe
          for (int j=0;j<20;j++){ long s=mem.getInt(sp.getAddress(vt+j*4L))&0xffffffffL; if(s<0x401000L||s>=0x60e000L)break; pw.println("\n== slot["+j+"] =="); disasmRange(s,140); }
        }
      } catch(Exception e){}
    }
    pw.close(); println("wrote re/slider_raw.txt  hits="+hits.size()+" fns="+fns.size());
  }
}
