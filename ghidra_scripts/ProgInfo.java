import ghidra.app.script.GhidraScript;
public class ProgInfo extends GhidraScript {
  public void run() throws Exception {
    println("NAME=" + currentProgram.getName());
    println("EXECPATH=" + currentProgram.getExecutablePath());
    println("MD5=" + currentProgram.getExecutableMD5());
    println("FORMAT=" + currentProgram.getExecutableFormat());
    println("IMAGEBASE=" + currentProgram.getImageBase());
    println("FUNCS=" + currentProgram.getFunctionManager().getFunctionCount());
    // sanity: 1.40 has "Tribes-release.pdb"; check a known 1.40 addr decompiles
    println("LANG=" + currentProgram.getLanguageID());
  }
}
