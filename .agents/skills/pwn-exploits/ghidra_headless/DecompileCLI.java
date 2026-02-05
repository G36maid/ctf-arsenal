// 反編譯所有函式並輸出至 Console
// @category CTF
// @author Gemini_Assistant

import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;

public class DecompileCLI extends GhidraScript {

    @Override
    public void run() throws Exception {
        DecompInterface ifc = new DecompInterface();
        ifc.openProgram(currentProgram);

        FunctionIterator iter = currentProgram.getFunctionManager().getFunctions(true);
        while (iter.hasNext() && !monitor.isCancelled()) {
            Function f = iter.next();
            DecompileResults res = ifc.decompileFunction(f, 0, monitor);
            
            if (res.decompileCompleted()) {
                println("--- Function: " + f.getName() + " ---");
                println(res.getDecompiledFunction().getC());
            }
        }
        ifc.dispose();
    }
}
