#!/usr/bin/env python3
"""
Angr Symbolic Execution Template for CTF
Automatic path exploration - "暴力解邏輯題的神器"

Usage:
    python angr_template.py [binary]

Common CTF Use Cases:
- Crack simple password checks
- Solve math puzzles
- Find inputs that reach specific code paths
- Reverse algorithmic checks

Prerequisites:
    1. Install: pip install angr
    2. Use Ghidra/Binary Ninja to find:
       - "Good Job" / success address
       - "Try Again" / failure address
       - Input mechanism (stdin/command line/format string)
"""

import angr
import claripy
import sys

# ===== 設定 =====
BINARY = "./vuln"  # 可從命令列參數修改
AUTO_LOAD_LIBS = False  # 絕大多數 CTF 題不需要載入 libc
TIMEOUT = 300  # 超時時間 (秒)

# ===== 地址設定 (必須手動用 Ghidra 找到) =====
# 使用 objdump -d vuln | grep -A5 "Good Job" 或者在 Ghidra 中搜尋字串
GOOD_ADDR = 0x401234  # 成功到達的位址 (print "Good Job" 的位置)
BAD_ADDR = 0x401236  # 失敗到達的位址 (print "Try Again" 的位置)


def solve_stdin_input(binary_path, good_addr, bad_addr):
    """
    從 stdin 讀取輸入的情況 (最常見)

    Example: scanf("%s", buf), gets(buf), read(0, buf, size)
    """
    print(f"[*] Loading binary: {binary_path}")
    p = angr.Project(binary_path, auto_load_libs=AUTO_LOAD_LIBS)

    print("[*] Creating entry state...")
    state = p.factory.entry_state()

    print("[*] Creating simulation manager...")
    simgr = p.factory.simulation_manager(state)

    print(f"[*] Exploring (timeout: {TIMEOUT}s)...")
    print(f"    Good address: {hex(good_addr)}")
    print(f"    Bad address: {hex(bad_addr)}")

    try:
        simgr.explore(find=good_addr, avoid=bad_addr)

        if simgr.found:
            print("[+] Solution found!")
            solution_state = simgr.found[0]

            # 取得 stdin 輸入
            stdin_data = solution_state.posix.dumps(sys.stdin.fileno())

            # 清理輸出 (去除 null bytes, 適當顯示)
            flag = stdin_data.replace(b"\x00", b"").decode("latin-1", errors="ignore")
            print(f"[+] Flag/Password: {flag}")
            print(f"[+] Raw bytes: {stdin_data}")

            return stdin_data
        else:
            print("[-] No solution found. Try:")
            print("    1. Check if GOOD_ADDR/BAD_ADDR are correct")
            print("    2. Increase timeout")
            print("    3. Verify binary is not obfuscated")
            return None

    except Exception as e:
        print(f"[-] Error: {e}")
        return None


def solve_symbolic_length(binary_path, good_addr, bad_addr, input_length=32):
    """
    指定輸入長度的符號執行

    Example: 需要 32 bytes 輸入的情況
    """
    print(f"[*] Loading binary: {binary_path}")
    p = angr.Project(binary_path, auto_load_libs=AUTO_LOAD_LIBS)

    print(f"[*] Creating symbolic input (length: {input_length})...")
    flag_chars = [claripy.BVS(f"flag_{i}", 8) for i in range(input_length)]
    flag = claripy.Concat(*flag_chars)

    state = p.factory.entry_state(stdin=flag)

    # 限制輸入為可打印 ASCII (可選，加快速度)
    for char in flag_chars:
        state.solver.add(char >= 0x20)
        state.solver.add(char <= 0x7E)

    print("[*] Creating simulation manager...")
    simgr = p.factory.simulation_manager(state)

    print(f"[*] Exploring...")
    try:
        simgr.explore(find=good_addr, avoid=bad_addr)

        if simgr.found:
            print("[+] Solution found!")
            solution = simgr.found[0]

            # 取得解
            flag_value = solution.posix.dumps(0)
            flag_str = flag_value.decode("latin-1", errors="ignore")
            print(f"[+] Flag: {flag_str}")

            return flag_value
        else:
            print("[-] No solution found")
            return None

    except Exception as e:
        print(f"[-] Error: {e}")
        return None


def solve_format_string(binary_path, good_addr, bad_addr):
    """
    格式化字串輸入 (例如：flag{%s}, Password: %s)

    Example: printf("Password: %s\n", password)
    """
    print(f"[*] Loading binary: {binary_path}")
    p = angr.Project(binary_path, auto_load_libs=AUTO_LOAD_LIBS)

    # 使用 prefix + 符號變量
    prefix = b"flag{"
    suffix = b"}"
    flag_length = 20

    flag_chars = [claripy.BVS(f"flag_{i}", 8) for i in range(flag_length)]
    flag = claripy.Concat(*flag_chars)

    stdin_input = prefix + flag + suffix

    print("[*] Creating entry state with format string...")
    state = p.factory.entry_state(stdin=stdin_input)

    print("[*] Creating simulation manager...")
    simgr = p.factory.simulation_manager(state)

    print(f"[*] Exploring...")
    try:
        simgr.explore(find=good_addr, avoid=bad_addr)

        if simgr.found:
            print("[+] Solution found!")
            solution = simgr.found[0]
            flag_value = solution.posix.dumps(0)
            print(f"[+] Full input: {flag_value}")
            return flag_value
        else:
            print("[-] No solution found")
            return None

    except Exception as e:
        print(f"[-] Error: {e}")
        return None


def solve_argv_input(binary_path, good_addr, bad_addr, argv_idx=1):
    """
    從命令列參數讀取輸入的情況

    Example: ./vuln password
    """
    print(f"[*] Loading binary: {binary_path}")
    p = angr.Project(binary_path, auto_load_libs=AUTO_LOAD_LIBS)

    print(f"[*] Creating argv[{argv_idx}] symbolic input...")
    argv = [binary_path]
    arg = claripy.BVS("argv_1", 50 * 8)  # 50 characters
    argv.append(arg)

    state = p.factory.entry_state(args=argv)

    print("[*] Creating simulation manager...")
    simgr = p.factory.simulation_manager(state)

    print(f"[*] Exploring...")
    try:
        simgr.explore(find=good_addr, avoid=bad_addr)

        if simgr.found:
            print("[+] Solution found!")
            solution = simgr.found[0]
            # argv 在 state 的記憶體中，需要自行提取
            # 這裡只是一個框架，實際提取方式可能因題目而異
            print("[+] Arg found (check memory)")
            return None
        else:
            print("[-] No solution found")
            return None

    except Exception as e:
        print(f"[-] Error: {e}")
        return None


def solve_with_constraint(binary_path, good_addr, bad_addr):
    """
    自定義約束條件

    Example: 輸入必須是數字，或特定格式
    """
    print(f"[*] Loading binary: {binary_path}")
    p = angr.Project(binary_path, auto_load_libs=AUTO_LOAD_LIBS)

    # 創建符號變量
    flag = claripy.BVS("flag", 64)  # 64 bits

    state = p.factory.entry_state(stdin=flag)

    # 添加自定義約束
    # 例如：輸入必須是正整數
    # state.solver.add(flag >= 0)

    print("[*] Creating simulation manager...")
    simgr = p.factory.simulation_manager(state)

    print(f"[*] Exploring...")
    try:
        simgr.explore(find=good_addr, avoid=bad_addr)

        if simgr.found:
            print("[+] Solution found!")
            solution = simgr.found[0]
            flag_value = solution.solver.eval(flag)
            print(f"[+] Flag: {flag_value}")
            return flag_value
        else:
            print("[-] No solution found")
            return None

    except Exception as e:
        print(f"[-] Error: {e}")
        return None


def find_addresses_from_strings(binary_path, success_strs, fail_strs):
    """
    Helper: 從字串找到地址 (Ghidra 也可以做這件事)

    Args:
        binary_path: 二進位檔路徑
        success_strs: 成功字串列表, 例如 [b"Good Job", b"Success"]
        fail_strs: 失敗字串列表, 例如 [b"Try Again", b"Wrong"]

    Returns:
        (good_addr, bad_addr) or (None, None)
    """
    try:
        p = angr.Project(binary_path, auto_load_libs=False)
        cfg = p.analyses.CFGFast()

        # 找到包含這些字串的基本區塊
        good_addr = None
        bad_addr = None

        for func in cfg.functions.values():
            for block in func.blocks:
                block_data = block.bytes
                for s in success_strs:
                    if s in block_data:
                        good_addr = block.addr
                        print(f"[+] Found success string '{s}' at {hex(good_addr)}")
                        break
                for s in fail_strs:
                    if s in block_data:
                        bad_addr = block.addr
                        print(f"[+] Found fail string '{s}' at {hex(bad_addr)}")
                        break

        return good_addr, bad_addr
    except Exception as e:
        print(f"[-] Error finding addresses: {e}")
        return None, None


def main():
    """主執行函數"""

    # 從命令列參數取得 binary 路徑
    if len(sys.argv) > 1:
        binary = sys.argv[1]
    else:
        binary = BINARY

    print(f"[*] Angr Symbolic Execution Template")
    print(f"[*] Target: {binary}")

    # ===== 選擇你需要的模式 =====

    # 1. 基本 stdin 輸入 (最常用)
    solve_stdin_input(binary, GOOD_ADDR, BAD_ADDR)

    # 2. 指定長度輸入
    # solve_symbolic_length(binary, GOOD_ADDR, BAD_ADDR, input_length=32)

    # 3. 格式化字串 (flag{...})
    # solve_format_string(binary, GOOD_ADDR, BAD_ADDR)

    # 4. 命令列參數輸入
    # solve_argv_input(binary, GOOD_ADDR, BAD_ADDR, argv_idx=1)

    # 5. 自定義約束
    # solve_with_constraint(binary, GOOD_ADDR, BAD_ADDR)

    # ===== 自動找地址 (可選) =====
    # print("\n[*] Trying to auto-find addresses...")
    # good, bad = find_addresses_from_strings(
    #     binary,
    #     success_strs=[b"Good Job", b"Success", b"flag{"],
    #     fail_strs=[b"Try Again", b"Wrong", b"Fail"]
    # )
    # if good and bad:
    #     print(f"[+] Auto-found: Good={hex(good)}, Bad={hex(bad)}")
    #     # solve_stdin_input(binary, good, bad)


if __name__ == "__main__":
    main()
