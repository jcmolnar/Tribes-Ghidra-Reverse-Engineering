// Apply readable names to the BitStream read primitives + the unpack guard, so PersistWalker's
// decompiles read `readInt(stream,10)` etc. instead of `FUN_00582f70(...)`. Identities confirmed by
// decompiling each (see DumpHelpers.java output). Names persist into the saved program.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;

public class NameBitStream extends GhidraScript {
  // address -> name
  static final long[]   A = {
    0x00582f70L, 0x00582ea8L, 0x00583064L, 0x00583184L, 0x00588db8L, 0x0055199cL
  };
  static final String[] N = {
    "BS_readInt",            // uint readInt(stream, numBits) — mask of readBits
    "BS_readBits",           // void readBits(stream, numBits, void* dst) — raw bit reader
    "BS_readFloat",          // float readFloat(stream, numBits) — single float (FPU)
    "BS_readNormalVector",   // void readNormalVector(stream, void* vec) — 2 floats + derived z + sign
    "BS_readSTString",       // void readSTString(stream, int caseSen) — string -> string-table intern
    "unpackGuard_invalidPkt" // bool guard: aborts ("Invalid packet.") when packet marked invalid
  };

  public void run() throws Exception {
    AddressSpace sp=currentProgram.getAddressFactory().getDefaultAddressSpace();
    FunctionManager fm=currentProgram.getFunctionManager();
    for(int i=0;i<A.length;i++){
      Address a=sp.getAddress(A[i]);
      Function f=fm.getFunctionAt(a);
      if(f==null){ try{ disassemble(a); f=createFunction(a,null);}catch(Exception e){} }
      if(f==null){ println("  [skip] no function @0x"+Long.toHexString(A[i])); continue; }
      String old=f.getName();
      f.setName(N[i], SourceType.USER_DEFINED);
      println("  0x"+Long.toHexString(A[i])+"  "+old+" -> "+N[i]);
    }
    println("done.");
  }
}
