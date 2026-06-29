import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.app.decompiler.*;
import java.io.*;

// Find the texture-cache size limit in Tribes.exe 1.40.655: the "Maximum width of bitmap"
// assert + its function (the bitmap-cache upload), so we know the exact max texture size
// and the overflow that crashes on oversized (upscaled) textures.
public class TexCacheLimit extends GhidraScript {
  DecompInterface di; PrintWriter pw;
  public void run() throws Exception {
    di = new DecompInterface(); di.openProgram(currentProgram);
    pw = new PrintWriter(new FileWriter("C:\\Users\\Joe\\Desktop\\Tribes Browser Based\\re\\texcachelimit.txt"));
    FunctionManager fm = currentProgram.getFunctionManager();
    String[] anchors = { "Maximum width of bitmap", "Maximum width", "bitmap is 256", "g_bitmap", "gOGLTx" };
    java.util.HashSet<String> done = new java.util.HashSet<String>();
    DataIterator dit = currentProgram.getListing().getDefinedData(true);
    while (dit.hasNext()) {
      Data d = dit.next();
      Object v = d.getValue();
      if (!(v instanceof String)) continue;
      String s = (String) v;
      boolean hit = false;
      for (String a : anchors) if (s.contains(a)) { hit = true; break; }
      if (!hit) continue;
      pw.println("\n##### STRING @" + d.getAddress() + " : " + s.replace("\n"," ") + " #####");
      for (Reference ref : getReferencesTo(d.getAddress())) {
        Function f = fm.getFunctionContaining(ref.getFromAddress());
        if (f == null) continue;
        String key = f.getEntryPoint().toString();
        if (done.contains(key)) continue; done.add(key);
        pw.println("---- function " + f.getEntryPoint() + " " + f.getName() + " (ref @" + ref.getFromAddress() + ") ----");
        DecompileResults r = di.decompileFunction(f, 60, monitor);
        if (r != null && r.getDecompiledFunction() != null) pw.println(r.getDecompiledFunction().getC());
      }
    }
    pw.close(); println("wrote texcachelimit.txt");
  }
}
