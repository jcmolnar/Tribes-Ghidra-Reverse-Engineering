// GhostCat140 — dump datablock unpack (vtable slot 1) + ghost unpackUpdate (slot 26) wire formats.
// Slots verified: DataBlockEvent::unpack calls (*data+4)=slot1 ; simNetObject.h order getGhostTag=24,
// packUpdate=25, unpackUpdate=26, buildScopeAndCameraInfo=27. Output: re/ghostcat_140.txt
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.app.decompiler.*;
import java.io.*;

public class GhostCat140 extends GhidraScript {
  FunctionManager fm; DecompInterface di; AddressSpace sp;
  ghidra.program.model.mem.Memory mem;
  PrintWriter pw;
  long u32(long va) throws Exception { return mem.getInt(sp.getAddress(va)) & 0xffffffffL; }
  void deco(String label, long vt, int slot) {
    try {
      long ea=u32(vt + slot*4L);
      pw.println("\n======== "+label+"  (vtbl=0x"+Long.toHexString(vt)+" slot"+slot+" -> 0x"+Long.toHexString(ea)+") ========");
      Address a=sp.getAddress(ea); Function f=fm.getFunctionAt(a); if(f==null)f=fm.getFunctionContaining(a);
      if(f==null){ try{disassemble(a); f=createFunction(a,null);}catch(Exception e){} }
      if(f==null){ pw.println("  <no func>"); return; }
      DecompileResults r=di.decompileFunction(f,60,monitor);
      pw.println((r!=null&&r.decompileCompleted())? r.getDecompiledFunction().getC() : "  <fail>");
    } catch(Exception e){ pw.println("  <err "+e+">"); }
  }
  // {name, vtableHex}
  static final String[][] DB = {
    {"GameBaseData","65a454"},{"ShapeBaseData","65f3d4"},{"StaticBaseData","6600e0"},
    {"PlayerData","65d224"},{"ItemImageData","65d3b0"},{"ItemData","65b03c"},
    {"ProjectileData","65dfe0"},{"BulletData","65ddbc"},{"MoveableData","65c800"},
    {"VehicleData","66099c"},{"SensorData","65f250"},{"GrenadeData","65e228"},
    {"RocketDumbData","65eb44"},{"ExplosionData","64bf00"},{"DebrisData","64a790"},
    {"MarkerData","65b230"},{"MineData","65b428"},{"LaserData","65e45c"},
    {"SeekingMissileData","65ed80"},{"RepairEffectData","65e920"},{"TriggerData","660508"},
    {"TurretData","660770"},{"StaticShapeData","64a414"},{"FlierData","64a43c"},
    {"DamageSkinData","65f634"},{"SoundData","65fbcc"},{"SoundProfileData","65fbdc"},
  };
  static final String[][] GH = {
    {"GameBase","65a284"},{"ShapeBase","65f45c"},{"StaticBase","65fce4"},
    {"Player","65cea4"},{"Item","65addc"},{"Vehicle","660784"},{"Projectile","65de04"},
    {"Bullet","65dbdc"},{"StaticShape","65ff04"},{"Sensor","65f07c"},{"Turret","66058c"},
    {"Moveable","65c5bc"},{"Flier","659ef4"},{"Lightning","65e4dc"},{"TargetLaser","65eda4"},
    {"RepairEffect","65e73c"},{"Marker","65b09c"},{"Mine","65b244"},{"Explosion","64bcd4"},
    {"Debris","64a484"},
  };
  public void run() throws Exception {
    fm=currentProgram.getFunctionManager(); sp=currentProgram.getAddressFactory().getDefaultAddressSpace();
    mem=currentProgram.getMemory(); di=new DecompInterface(); di.openProgram(currentProgram);
    pw=new PrintWriter(new BufferedWriter(new FileWriter(System.getProperty("user.home")+"/ghostcat_140.txt")));
    pw.println("TRIBES 1.40.655 — datablock unpack (slot1) + ghost unpackUpdate (slot26) wire formats");
    pw.println("Legend: readInt=FUN_0040fd10(bits) writeInt=FUN_0040fd50(v,bits); netcode gate = DAT_006d0ff8 (serverNetcodeVersion) byteswap<0x101");
    pw.println("\n#################### DATABLOCK ::unpack (vtable slot 1) ####################");
    for(String[] d: DB){ deco(d[0], Long.parseLong(d[1],16), 1); monitor.checkCancelled(); }
    pw.println("\n\n#################### GHOST ::unpackUpdate (vtable slot 26) ####################");
    for(String[] g: GH){ deco(g[0], Long.parseLong(g[1],16), 26); monitor.checkCancelled(); }
    // sanity: Player packUpdate (slot25) to confirm 25=write / 26=read
    pw.println("\n\n#################### SANITY: Player packUpdate (slot 25) ####################");
    deco("Player::packUpdate", 0x65cea4L, 25);
    pw.close();
    println("wrote re/ghostcat_140.txt ("+DB.length+" datablocks, "+GH.length+" ghosts)");
  }
}
