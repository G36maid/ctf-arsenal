#!/usr/bin/env python3
from z3 import *

p = [BitVec(f"p{i}", 8) for i in range(15)]

solver = Solver()

solver.add(p[0] == ord("C"))
solver.add(p[1] == ord("S"))
solver.add(p[2] == ord("C"))
solver.add(p[3] == ord("2"))
solver.add(p[4] == ord("0"))
solver.add(p[5] == ord("2"))
solver.add(p[6] == ord("5"))

solver.add(Or(p[7] == ord("H"), p[7] == ord("P"), p[7] == ord("X")))
solver.add(Or(p[7] == ord("H"), p[7] == ord("P"), p[7] == ord("X")))

for i in range(7, 15):
    solver.add(p[i] >= 0x41)
    solver.add(p[i] <= 0x5A)

solver.add(Sum([ZeroExt(24, p[i]) for i in range(15)]) == 0x415)

xor_all = p[0]
for i in range(1, 15):
    xor_all = xor_all ^ p[i]
solver.add(xor_all == 0x49)

sum_squares_7_15 = Sum([ZeroExt(24, p[i]) * ZeroExt(24, p[i]) for i in range(7, 15)])
solver.add(sum_squares_7_15 % 100 == 0x3D)

solver.add(Sum([ZeroExt(24, p[i]) for i in range(7, 15)]) == 0x273)

solver.add(p[10] == p[9])

xor_8_15 = p[8]
for i in range(9, 15):
    xor_8_15 = xor_8_15 ^ p[i]
solver.add(xor_8_15 == 0x1F)

solver.add(p[7] ^ p[8] == 0x11)
solver.add(ZeroExt(24, p[9]) * ZeroExt(24, p[7]) * ZeroExt(24, p[8]) == 0x695F0)

solver.add(p[11] ^ p[12] == 0x18)
solver.add(UGT(p[11], p[12]))
solver.add(UGT(p[13], p[14]))

sum_cubes_7_15 = Sum(
    [ZeroExt(24, p[i]) * ZeroExt(24, p[i]) * ZeroExt(24, p[i]) for i in range(7, 15)]
)
solver.add(sum_cubes_7_15 == 0x3C3C15)

sum_products = Sum([ZeroExt(24, p[i]) * ZeroExt(24, p[i + 1]) for i in range(7, 14)])
solver.add(sum_products == 0xAA70)

xor_odd = p[3]
for i in range(5, 14, 2):
    xor_odd = xor_odd ^ p[i]
solver.add(xor_odd == 0x55)

solver.add(
    (ZeroExt(32, p[13]) * ZeroExt(32, p[12]) * ZeroExt(32, p[11]) * ZeroExt(32, p[10]))
    % 10000
    == 0x1DD6
)

print("[*] Solving with Z3...")
if solver.check() == sat:
    model = solver.model()
    password = "".join([chr(model[p[i]].as_long()) for i in range(15)])
    print(f"[+] PASSWORD: {password}")
else:
    print("[-] No solution")
