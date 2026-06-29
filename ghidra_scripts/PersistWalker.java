// PersistWalker — enumerate EVERY persistent class in T1Vista.exe and dump its wire format.
//
// *** WARNING: the NAME labels in this dump are OFF BY ONE. In this Borland binary, the descriptor pointer at
// *** vtable V+0x1c points to the descriptor of the class at vtable V+0x34 (the NEXT vtable), so descr+0x30
// *** gives the ADJACENT class's name, not V's. The unpack/pack ADDRESSES per vtable are correct; only the
// *** NAME join is wrong. For correct names use EventMap.java (realName(V) = string at (*((V-0x34)+0x1c))+0x30)
// *** -> re/event_cluster.txt. This cost a real debugging detour (mislabeled PlayerCommandEvent as Objective).
//
// Discovered layout (verified against TeamObjectiveEvent / PlayerSelectCmdrEvent / PlayerAdd / etc.):
//   A persistent class vtable V has:
//     *(V+0x0c) = pack(SimManager*, PacketStream*, BitStream*)
//     *(V+0x10) = unpack(SimManager*, PacketStream*, BitStream*)
//     *(V+0x1c) = descriptor D
//   and the descriptor D has the class-name C-string inline at D+0x30.
//
// The persistent TAG (classTag, 1024..1151 = readInt(7)+1024 in EventManager::readPacket) is assigned
// at startup into the runtime fastTable, which is empty in the static image -- so we do NOT recover the
// tag from the binary. Instead we join class NAME -> tag using the table from program/inc/FearDcl.h.
//
// Output: a summary table (to the log) + full unpack() decompiles (to re\persist_dump.txt) for every
// persistent class found, so the exact readInt(N)/readFloat(N)/readString widths can be read off and
// compared against our hand-mirrored stubs (the 0.8.5 desync hunt).
//
// Run headless against the existing project:
//   analyzeHeadless re\proj tribes -process T1Vista.exe -noanalysis \
//       -scriptPath re\ghidra_scripts -postScript PersistWalker.java
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.app.decompiler.*;
import java.io.*;
import java.util.*;

public class PersistWalker extends GhidraScript {
  Memory mem; AddressSpace sp; FunctionManager fm; DecompInterface di;
  long textMin, textMax;

  // name -> classTag, from program/inc/FearDcl.h (engine + Kronos app event tags).
  static final String[] TAG_NAME = {
    "PlayerAddEvent","PlayerRemoveEvent","DeltaScoreEvent","TeamAddEvent","PlayerTeamChangeEvent",
    "PlayerSayEvent","DataBlockEvent","MissionResetEvent","LocSoundEvent","TargetNameEvent",
    "VoiceEvent","SoundEvent","PingPLEvent","PlayerSkinEvent","TeamObjectiveEvent"
  };
  static final int[] TAG_VAL = {
    1099,1100,1101,1103,1106, 1107,1112,1113,1116,1117, 1119,1120,1121,1122,1024
  };
  int tagFor(String name){
    for(int i=0;i<TAG_NAME.length;i++) if(TAG_NAME[i].equals(name)) return TAG_VAL[i];
    return -1;
  }

  long u32(long va) throws MemoryAccessException { return mem.getInt(sp.getAddress(va)) & 0xffffffffL; }
  boolean inText(long v){ return v>=textMin && v<textMax; }

  // Read a candidate class name at address va; return null unless it looks like a C++ class identifier.
  String className(long va){
    try{
      StringBuilder s=new StringBuilder();
      Address a=sp.getAddress(va);
      for(int i=0;i<48;i++){
        int b=mem.getByte(a.add(i))&0xff;
        if(b==0) break;
        boolean ok=(b>='A'&&b<='Z')||(b>='a'&&b<='z')||(b>='0'&&b<='9')||b=='_'||b==':';
        if(!ok) return null;
        s.append((char)b);
      }
      String r=s.toString();
      if(r.length()<4) return null;
      char c0=r.charAt(0);
      if(c0<'A'||c0>'Z') return null;        // class names start uppercase here
      return r;
    }catch(Exception e){ return null; }
  }

  String decompile(long entry){
    Address pa=sp.getAddress(entry);
    Function f=fm.getFunctionAt(pa);
    if(f==null) f=fm.getFunctionContaining(pa);
    if(f==null){ try{ disassemble(pa); f=createFunction(pa,null); }catch(Exception e){} }
    if(f==null) return "  <no function @0x"+Long.toHexString(entry)+">";
    DecompileResults r=di.decompileFunction(f,60,monitor);
    if(r!=null && r.decompileCompleted()) return r.getDecompiledFunction().getC();
    return "  <decompile failed @0x"+Long.toHexString(entry)+">";
  }

  static class Cls { long vt,descr,pack,unpack; String name; int tag; }

  public void run() throws Exception {
    mem=currentProgram.getMemory();
    sp=currentProgram.getAddressFactory().getDefaultAddressSpace();
    fm=currentProgram.getFunctionManager();
    di=new DecompInterface(); di.openProgram(currentProgram);

    MemoryBlock textB=mem.getBlock(".text");
    textMin=textB.getStart().getOffset(); textMax=textB.getEnd().getOffset();
    println("[.text] 0x"+Long.toHexString(textMin)+" .. 0x"+Long.toHexString(textMax));

    // Scan every initialized, non-.text block for persistent vtables.
    Map<Long,Cls> found=new LinkedHashMap<Long,Cls>();
    Set<String> seenNames=new HashSet<String>();
    for(MemoryBlock b: mem.getBlocks()){
      if(!b.isInitialized() || b.getName().equals(".text")) continue;
      long start=b.getStart().getOffset(), end=b.getEnd().getOffset()-0x20;
      for(long V=start; V<=end; V+=4){
        long pack,unpack,descr;
        try{
          pack  = u32(V+0x0c);
          unpack= u32(V+0x10);
          descr = u32(V+0x1c);
        }catch(Exception e){ continue; }
        if(!inText(pack) || !inText(unpack)) continue;        // vtable slots must be code
        if(pack==0||unpack==0) continue;
        String nm=className(descr+0x30);
        if(nm==null) continue;
        if(!seenNames.add(nm)) continue;                       // first vtable per class name
        Cls c=new Cls(); c.vt=V; c.descr=descr; c.pack=pack; c.unpack=unpack; c.name=nm; c.tag=tagFor(nm);
        found.put(V,c);
      }
    }

    List<Cls> all=new ArrayList<Cls>(found.values());
    Collections.sort(all,new Comparator<Cls>(){ public int compare(Cls a,Cls b){ return a.name.compareTo(b.name);} });
    println("\n==== "+all.size()+" persistent classes found ====");
    println(String.format("%-32s %6s %-10s %-10s %-10s %-10s","NAME","TAG","VTABLE","DESCR","PACK","UNPACK"));
    for(Cls c: all)
      println(String.format("%-32s %6s 0x%08x 0x%08x 0x%08x 0x%08x",
        c.name, c.tag>=0?Integer.toString(c.tag):"-", c.vt, c.descr, c.pack, c.unpack));

    // Full unpack() decompiles to file (the wire-format ground truth).
    File out=new File("C:\\Users\\Joe\\Desktop\\Tribes Browser Based\\re\\persist_dump.txt");
    PrintWriter pw=new PrintWriter(new BufferedWriter(new FileWriter(out)));
    pw.println("Persistent classes in T1Vista.exe (Borland C++) — unpack() wire formats");
    pw.println("vtable: +0x0c=pack +0x10=unpack +0x1c=descr ; descr+0x30=name\n");
    for(Cls c: all){
      pw.println("\n================================================================");
      pw.println(c.name+"   tag="+(c.tag>=0?c.tag:"?")+"   vtable=0x"+Long.toHexString(c.vt)
                 +"   unpack=0x"+Long.toHexString(c.unpack)+"   pack=0x"+Long.toHexString(c.pack));
      pw.println("================================================================");
      pw.println("---- unpack ----");
      pw.println(decompile(c.unpack));
      monitor.checkCancelled();
    }
    pw.close();
    println("\nWrote unpack decompiles for "+all.size()+" classes -> "+out.getPath());
  }
}
