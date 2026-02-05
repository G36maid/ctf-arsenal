# @category CTF
# @keybinding
# @menupath
# @toolbar

from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

# 初始化反編譯介面
ifc = DecompInterface()
ifc.openProgram(currentProgram)

# 遍歷所有函式並反編譯
functions = currentProgram.getFunctionManager().getFunctions(True)
for func in functions:
    results = ifc.decompileFunction(func, 0, ConsoleTaskMonitor())
    if results.decompileCompleted():
        print(f"--- Function: {func.getName()} ---")
        print(results.getDecompiledFunction().getC())
