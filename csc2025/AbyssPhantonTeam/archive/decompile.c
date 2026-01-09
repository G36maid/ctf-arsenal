
/* WARNING: Removing unreachable block (ram,0x004024bb) */
/* WARNING: Removing unreachable block (ram,0x00402427) */
/* WARNING: Removing unreachable block (ram,0x0040239a) */
/* WARNING: Removing unreachable block (ram,0x004022bf) */
/* WARNING: Removing unreachable block (ram,0x00402227) */
/* WARNING: Removing unreachable block (ram,0x0040218f) */
/* WARNING: Removing unreachable block (ram,0x00402102) */
/* WARNING: Removing unreachable block (ram,0x004021dd) */
/* WARNING: Removing unreachable block (ram,0x00402273) */
/* WARNING: Removing unreachable block (ram,0x00402314) */
/* WARNING: Removing unreachable block (ram,0x004023df) */
/* WARNING: Removing unreachable block (ram,0x00402471) */
/* WARNING: Removing unreachable block (ram,0x0040250e) */
/* WARNING: Removing unreachable block (ram,0x00402662) */
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */
/* Golang function info: Flags: []
   Golang source: /usr/local/go/src/internal/cpu/cpu_x86.go:50
   Golang stacktrace signature: func internal/cpu.doinit() ???
   Golang signature [from_snapshot]: func internal/cpu.doinit() */

void internal/cpu::internal/cpu.doinit(void)

{
  internal/cpu.option (*paiVar1) [6];
  uint32 ecxArg;
  uint extraout_RBX;
  uint newLen;
  runtime.slice rVar2;
  multireturn{uint32;uint32;uint32;uint32} mVar3;
  multireturn{uint32;uint32} mVar4;
  uint local_58;
  uint32 local_50;
  dword local_4c;
  dword local_48;
  dword local_44;

  while (&stack0x00000000 <= CURRENT_G.stackguard0) {
    runtime::runtime.morestack_noctxt();
  }
  DAT_00555cf0 = runtime::runtime.newobject
                           ((internal/abi.Type *)&[6]internal/cpu.option___Array_type);
  (*DAT_00555cf0)[0].Name.len = 3;
  (*DAT_00555cf0)[0].Name.str = &DAT_004b4492;
  (*DAT_00555cf0)[0].Feature = (bool *)&DAT_005a92e1;
  (*DAT_00555cf0)[1].Name.len = 3;
  (*DAT_00555cf0)[1].Name.str = &DAT_004b4495;
  (*DAT_00555cf0)[1].Feature = (bool *)&DAT_005a92e0;
  (*DAT_00555cf0)[2].Name.len = 4;
  (*DAT_00555cf0)[2].Name.str = &DAT_004b45eb;
  (*DAT_00555cf0)[2].Feature = (bool *)&DAT_005a92e6;
  (*DAT_00555cf0)[3].Name.len = 9;
  (*DAT_00555cf0)[3].Name.str = &DAT_004b4dfe;
  (*DAT_00555cf0)[3].Feature = (bool *)&DAT_005a92e9;
  (*DAT_00555cf0)[4].Name.len = 6;
  (*DAT_00555cf0)[4].Name.str = &DAT_004b4851;
  (*DAT_00555cf0)[4].Feature = (bool *)&DAT_005a92eb;
  (*DAT_00555cf0)[5].Name.len = 3;
  (*DAT_00555cf0)[5].Name.str = &DAT_004b4498;
  (*DAT_00555cf0)[5].Feature = (bool *)&DAT_005a92ec;
  DAT_00555cf8 = 6;
  DAT_00555d00 = 6;
  internal/cpu.getGOAMD64level();
  newLen = extraout_RBX;
  if ((sdword)local_58 < 2) {
    newLen = DAT_00555cf8 + 5;
    if (DAT_00555d00 < newLen) {
      rVar2 = runtime::runtime.growslice
                        (DAT_00555cf0,newLen,DAT_00555d00,5,
                         (internal/abi.Type *)&internal/cpu.option___Struct_type);
      DAT_00555d00 = rVar2.cap;
      newLen = rVar2.len;
      DAT_00555cf0 = (internal/cpu.option (*) [6])rVar2.array;
    }
    paiVar1 = DAT_00555cf0;
    DAT_00555cf8 = newLen;
    DAT_00555cf0[-1][newLen + 1].Name.len = 6;
    paiVar1[-1][newLen + 1].Specified = false;
    paiVar1[-1][newLen + 1].Enable = false;
    paiVar1[-1][newLen + 1].Name.str = &DAT_004b4857;
    paiVar1[-1][newLen + 1].Feature = (bool *)&DAT_005a92ea;
    paiVar1[-1][newLen + 2].Name.len = 4;
    paiVar1[-1][newLen + 2].Specified = false;
    paiVar1[-1][newLen + 2].Enable = false;
    paiVar1[-1][newLen + 2].Name.str = &DAT_004b45ef;
    paiVar1[-1][newLen + 2].Feature = (bool *)&DAT_005a92ed;
    paiVar1[-1][newLen + 3].Name.len = 5;
    paiVar1[-1][newLen + 3].Specified = false;
    paiVar1[-1][newLen + 3].Enable = false;
    paiVar1[-1][newLen + 3].Name.str = &DAT_004b4706;
    paiVar1[-1][newLen + 3].Feature = (bool *)&DAT_005a92ef;
    paiVar1[-1][newLen + 4].Name.len = 5;
    paiVar1[-1][newLen + 4].Specified = false;
    paiVar1[-1][newLen + 4].Enable = false;
    paiVar1[-1][newLen + 4].Name.str = &DAT_004b470b;
    paiVar1[-1][newLen + 4].Feature = (bool *)&DAT_005a92f0;
    paiVar1[-1][newLen + 5].Name.len = 5;
    paiVar1[-1][newLen + 5].Specified = false;
    paiVar1[-1][newLen + 5].Enable = false;
    paiVar1[-1][newLen + 5].Name.str = &DAT_004b4710;
    paiVar1[-1][newLen + 5].Feature = (bool *)&DAT_005a92ee;
  }
  paiVar1 = (internal/cpu.option (*) [6])(local_58 & 0xffffffff);
  if ((sdword)local_58 < 3) {
    newLen = DAT_00555cf8 + 5;
    if (DAT_00555d00 < newLen) {
      rVar2 = runtime::runtime.growslice
                        (DAT_00555cf0,newLen,DAT_00555d00,5,
                         (internal/abi.Type *)&internal/cpu.option___Struct_type);
      DAT_00555d00 = rVar2.cap;
      newLen = rVar2.len;
      DAT_00555cf0 = (internal/cpu.option (*) [6])rVar2.array;
    }
    paiVar1 = DAT_00555cf0;
    DAT_00555cf8 = newLen;
    DAT_00555cf0[-1][newLen + 1].Name.len = 3;
    paiVar1[-1][newLen + 1].Specified = false;
    paiVar1[-1][newLen + 1].Enable = false;
    paiVar1[-1][newLen + 1].Name.str = &DAT_004b449b;
    paiVar1[-1][newLen + 1].Feature = (bool *)&DAT_005a92e2;
    paiVar1[-1][newLen + 2].Name.len = 4;
    paiVar1[-1][newLen + 2].Specified = false;
    paiVar1[-1][newLen + 2].Enable = false;
    paiVar1[-1][newLen + 2].Name.str = &DAT_004b45f3;
    paiVar1[-1][newLen + 2].Feature = (bool *)&DAT_005a92e3;
    paiVar1[-1][newLen + 3].Name.len = 4;
    paiVar1[-1][newLen + 3].Specified = false;
    paiVar1[-1][newLen + 3].Enable = false;
    paiVar1[-1][newLen + 3].Name.str = &DAT_004b45f7;
    paiVar1[-1][newLen + 3].Feature = (bool *)&DAT_005a92e4;
    paiVar1[-1][newLen + 4].Name.len = 4;
    paiVar1[-1][newLen + 4].Specified = false;
    paiVar1[-1][newLen + 4].Enable = false;
    paiVar1[-1][newLen + 4].Name.str = &DAT_004b45fb;
    paiVar1[-1][newLen + 4].Feature = (bool *)&DAT_005a92e5;
    paiVar1[-1][newLen + 5].Name.len = 3;
    paiVar1[-1][newLen + 5].Specified = false;
    paiVar1[-1][newLen + 5].Enable = false;
    paiVar1[-1][newLen + 5].Name.str = &DAT_004b449e;
    paiVar1[-1][newLen + 5].Feature = (bool *)&DAT_005a92e7;
  }
  mVar3 = internal/cpu.cpuid((uint32)paiVar1,(uint32)newLen);
  if (local_50 == 0) {
    return;
  }
  mVar3 = internal/cpu.cpuid(0x80000000,mVar3.~r1);
  _DAT_005a8be0 = local_50;
  mVar3 = internal/cpu.cpuid(local_50,mVar3.~r1);
  ecxArg = mVar3.~r1;
  DAT_005a92ed = (local_48 & 1) != 0;
  DAT_005a92e9 = (local_48 >> 1 & 1) != 0;
  DAT_005a92ee = (local_48 >> 9 & 1) != 0;
  DAT_005a92ef = (local_48 >> 0x13 & 1) != 0;
  DAT_005a92f0 = (local_48 >> 0x14 & 1) != 0;
  DAT_005a92ea = (local_48 >> 0x17 & 1) != 0;
  DAT_005a92e0 = (local_48 >> 0x19 & 1) != 0;
  DAT_005a92e8 = (local_48 >> 0x1b & 1) != 0;
  DAT_005a92e7 = (local_48 >> 0xc & 1) != 0 && (bool)DAT_005a92e8;
  if ((local_48 >> 0x1b & 1) != 0) {
    mVar4 = internal/cpu.xgetbv();
    ecxArg = mVar4.~r1;
  }
  DAT_005a92e2 = 0;
  if (local_50 < 7) {
    return;
  }
  DAT_005a92e2 = 0;
  mVar3 = internal/cpu.cpuid(local_50,ecxArg);
  DAT_005a92e4 = (local_4c >> 3 & 1) != 0;
  DAT_005a92e3 = 0;
  DAT_005a92e5 = (local_4c >> 8 & 1) != 0;
  DAT_005a92e6 = (local_4c >> 9 & 1) != 0;
  DAT_005a92e1 = (local_4c >> 0x13 & 1) != 0;
  DAT_005a92ec = (local_4c >> 0x1d & 1) != 0;
  mVar3 = internal/cpu.cpuid(0x80000000,mVar3.~r1);
  if (0x80000000 < local_50) {
    internal/cpu.cpuid(0x80000001,mVar3.~r1);
    DAT_005a92eb = (local_44 >> 0x1b & 1) != 0;
    return;
  }
  return;
}

/* WARNING: Removing unreachable block (ram,0x0048760c) */
/* WARNING: Removing unreachable block (ram,0x004875b6) */
/* WARNING: Removing unreachable block (ram,0x00487562) */
/* WARNING: Removing unreachable block (ram,0x0048750c) */
/* WARNING: Removing unreachable block (ram,0x004874b6) */
/* WARNING: Removing unreachable block (ram,0x00487462) */
/* WARNING: Removing unreachable block (ram,0x0048740c) */
/* WARNING: Removing unreachable block (ram,0x004873b6) */
/* WARNING: Removing unreachable block (ram,0x00487362) */
/* WARNING: Removing unreachable block (ram,0x0048730c) */
/* WARNING: Removing unreachable block (ram,0x004872b6) */
/* WARNING: Removing unreachable block (ram,0x00487262) */
/* WARNING: Removing unreachable block (ram,0x0048720c) */
/* WARNING: Removing unreachable block (ram,0x004871b6) */
/* WARNING: Removing unreachable block (ram,0x00487162) */
/* WARNING: Removing unreachable block (ram,0x0048710c) */
/* WARNING: Removing unreachable block (ram,0x004870b6) */
/* WARNING: Removing unreachable block (ram,0x00487062) */
/* WARNING: Removing unreachable block (ram,0x00486fb6) */
/* WARNING: Removing unreachable block (ram,0x00486ed6) */
/* WARNING: Removing unreachable block (ram,0x00486df6) */
/* WARNING: Removing unreachable block (ram,0x00486d2c) */
/* WARNING: Removing unreachable block (ram,0x00486c4f) */
/* WARNING: Removing unreachable block (ram,0x00486cd3) */
/* WARNING: Removing unreachable block (ram,0x00486d85) */
/* WARNING: Removing unreachable block (ram,0x00486e65) */
/* WARNING: Removing unreachable block (ram,0x00486f45) */
/* WARNING: Removing unreachable block (ram,0x00487025) */
/* WARNING: Removing unreachable block (ram,0x0048708c) */
/* WARNING: Removing unreachable block (ram,0x004870e2) */
/* WARNING: Removing unreachable block (ram,0x00487136) */
/* WARNING: Removing unreachable block (ram,0x0048718c) */
/* WARNING: Removing unreachable block (ram,0x004871e2) */
/* WARNING: Removing unreachable block (ram,0x00487236) */
/* WARNING: Removing unreachable block (ram,0x0048728c) */
/* WARNING: Removing unreachable block (ram,0x004872e2) */
/* WARNING: Removing unreachable block (ram,0x00487336) */
/* WARNING: Removing unreachable block (ram,0x0048738c) */
/* WARNING: Removing unreachable block (ram,0x004873e2) */
/* WARNING: Removing unreachable block (ram,0x00487436) */
/* WARNING: Removing unreachable block (ram,0x0048748c) */
/* WARNING: Removing unreachable block (ram,0x004874e2) */
/* WARNING: Removing unreachable block (ram,0x00487536) */
/* WARNING: Removing unreachable block (ram,0x0048758c) */
/* WARNING: Removing unreachable block (ram,0x004875e2) */
/* WARNING: Removing unreachable block (ram,0x00487636) */
/* Golang function info: Flags: []
   Golang source: /usr/local/go/src/internal/syscall/windows/net_windows.go:32
   Golang stacktrace signature: func internal/syscall/windows.init() ??? */

void internal/syscall/windows::internal/syscall/windows.init(void)

{
  sync.Once *psVar1;
  bool *pbVar2;
  interface {} *piVar3;
  go.shape.bool *pgVar4;
  struct { F uintptr; X0 *interface {}; X1 *bool; X2 *go.shape.bool; X3 func() go.shape.bool; X4 *[3 ]uintptr }
  *psVar5;
  undefined1 *puVar6;
  interface {}_itab *piVar7;
  void *pvVar8;
  string s;
  string s_00;
  string s_01;
  string s_02;
  string s_03;
  string s_04;
  string s_05;

  piVar7 = (interface {}_itab *)0x0;
  pvVar8 = (void *)0x0;
  while (&stack0x00000000 <= CURRENT_G.stackguard0) {
    runtime::runtime.morestack_noctxt();
  }
  psVar1 = runtime::runtime.newobject((internal/abi.Type *)&sync::sync.Once___Struct_type);
  pbVar2 = runtime::runtime.newobject((internal/abi.Type *)&bool___Bool_type);
  piVar3 = runtime::runtime.newobject((internal/abi.Type *)&interface_{}___Interface_type);
  piVar3->tab = piVar7;
  piVar3->data = pvVar8;
  pgVar4 = runtime::runtime.newobject((internal/abi.Type *)&go.shape::go.shape.bool___Bool_type);
  psVar5 = runtime::runtime.newobject
                     ((internal/abi.Type *)
                      &
                      struct_{_F_uintptr;_X0_*interface_{};_X1_*bool;_X2_*go.shape.bool;_X3_func()_g o.shape.bool;_X4_*[3]uintptr_}___Struct_type
                     );
  psVar5->F = (uintptr)internal/syscall/windows.init.OnceValue[go.shape.bool].func1;
  psVar5->X0 = piVar3;
  psVar5->X1 = pbVar2;
  psVar5->X2 = pgVar4;
  psVar5->X3 = (func() go.shape.bool *)&PTR_internal/syscall/windows.glob..func1_004be888;
  psVar5->X4 = (uintptr (*) [3])&PTR_func()_bool___Func_type_004d7750;
  DAT_00555a08 = runtime::runtime.newobject
                           ((internal/abi.Type *)
                            &
                            struct_{_F_uintptr;_X0_*sync.Once;_X1_func();_X2_*bool;_X3_*interface_{} ;_X4_*go.shape.bool;_X5_*[3]uintptr_}___Struct_type
                           );
  DAT_00555a08->F = (uintptr)internal/syscall/windows.init.OnceValue[go.shape.bool].func2;
  DAT_00555a08->X0 = psVar1;
  DAT_00555a08->X1 = (func() *)psVar5;
  DAT_00555a08->X2 = pbVar2;
  DAT_00555a08->X3 = piVar3;
  DAT_00555a08->X4 = pgVar4;
  DAT_00555a08->X5 = (uintptr (*) [3])&PTR_func()_bool___Func_type_004d7750;
  s.len = 0xc;
  s.str = (uint8 *)"advapi32.dll";
  puVar6 = (undefined1 *)
           runtime::runtime.mapassign_faststr(&map[string]bool___Map_type,DAT_005559f0,s);
  *puVar6 = 1;
  DAT_00555a10 = runtime::runtime.newobject
                           ((internal/abi.Type *)&syscall::syscall.LazyDLL___Struct_type);
  (DAT_00555a10->Name).len = 0xc;
  (DAT_00555a10->Name).str = (uint8 *)"advapi32.dll";
  s_00.len = 0xc;
  s_00.str = (uint8 *)"iphlpapi.dll";
  puVar6 = (undefined1 *)
           runtime::runtime.mapassign_faststr(&map[string]bool___Map_type,DAT_005559f0,s_00);
  *puVar6 = 1;
  DAT_00555a18 = runtime::runtime.newobject
                           ((internal/abi.Type *)&syscall::syscall.LazyDLL___Struct_type);
  (DAT_00555a18->Name).len = 0xc;
  (DAT_00555a18->Name).str = (uint8 *)"iphlpapi.dll";
  s_01.len = 0xc;
  s_01.str = (uint8 *)"kernel32.dll";
  puVar6 = (undefined1 *)
           runtime::runtime.mapassign_faststr(&map[string]bool___Map_type,DAT_005559f0,s_01);
  *puVar6 = 1;
  DAT_00555a20 = runtime::runtime.newobject
                           ((internal/abi.Type *)&syscall::syscall.LazyDLL___Struct_type);
  (DAT_00555a20->Name).len = 0xc;
  (DAT_00555a20->Name).str = (uint8 *)"kernel32.dll";
  s_02.len = 0xc;
  s_02.str = (uint8 *)"netapi32.dll";
  puVar6 = (undefined1 *)
           runtime::runtime.mapassign_faststr(&map[string]bool___Map_type,DAT_005559f0,s_02);
  *puVar6 = 1;
  DAT_00555a28 = runtime::runtime.newobject
                           ((internal/abi.Type *)&syscall::syscall.LazyDLL___Struct_type);
  (DAT_00555a28->Name).len = 0xc;
  (DAT_00555a28->Name).str = (uint8 *)"netapi32.dll";
  s_03.len = 9;
  s_03.str = (uint8 *)"psapi.dll";
  puVar6 = (undefined1 *)
           runtime::runtime.mapassign_faststr(&map[string]bool___Map_type,DAT_005559f0,s_03);
  *puVar6 = 1;
  DAT_00555a30 = runtime::runtime.newobject
                           ((internal/abi.Type *)&syscall::syscall.LazyDLL___Struct_type);
  (DAT_00555a30->Name).len = 9;
  (DAT_00555a30->Name).str = (uint8 *)"psapi.dll";
  s_04.len = 0xb;
  s_04.str = (uint8 *)"userenv.dll";
  puVar6 = (undefined1 *)
           runtime::runtime.mapassign_faststr(&map[string]bool___Map_type,DAT_005559f0,s_04);
  *puVar6 = 1;
  DAT_00555a38 = runtime::runtime.newobject
                           ((internal/abi.Type *)&syscall::syscall.LazyDLL___Struct_type);
  (DAT_00555a38->Name).len = 0xb;
  (DAT_00555a38->Name).str = (uint8 *)"userenv.dll";
  s_05.len = 10;
  s_05.str = (uint8 *)"ws2_32.dll";
  puVar6 = (undefined1 *)
           runtime::runtime.mapassign_faststr(&map[string]bool___Map_type,DAT_005559f0,s_05);
  *puVar6 = 1;
  DAT_00555a40 = runtime::runtime.newobject
                           ((internal/abi.Type *)&syscall::syscall.LazyDLL___Struct_type);
  (DAT_00555a40->Name).len = 10;
  (DAT_00555a40->Name).str = (uint8 *)"ws2_32.dll";
  DAT_00551ed8 = DAT_00555a10;
  DAT_00551f18 = DAT_00555a10;
  DAT_00551f58 = DAT_00555a10;
  DAT_00551f98 = DAT_00555a10;
  DAT_00551fd8 = DAT_00555a10;
  DAT_00552018 = DAT_00555a10;
  DAT_00552058 = DAT_00555a10;
  DAT_00552098 = DAT_00555a10;
  DAT_005520d8 = DAT_00555a18;
  DAT_00552118 = DAT_00555a20;
  DAT_00552158 = DAT_00555a20;
  DAT_00552198 = DAT_00555a20;
  DAT_005521d8 = DAT_00555a20;
  DAT_00552218 = DAT_00555a20;
  DAT_00552258 = DAT_00555a20;
  DAT_00552298 = DAT_00555a20;
  DAT_005522d8 = DAT_00555a20;
  DAT_00552318 = DAT_00555a20;
  DAT_00552358 = DAT_00555a20;
  DAT_00552398 = DAT_00555a20;
  DAT_005523d8 = DAT_00555a20;
  DAT_00552418 = DAT_00555a20;
  DAT_00552458 = DAT_00555a20;
  DAT_00552498 = DAT_00555a20;
  DAT_005524d8 = DAT_00555a20;
  DAT_00552518 = DAT_00555a20;
  DAT_00552558 = DAT_00555a20;
  DAT_00552598 = DAT_00555a20;
  DAT_005525d8 = DAT_00555a28;
  DAT_00552618 = DAT_00555a28;
  DAT_00552658 = DAT_00555a28;
  DAT_00552698 = DAT_00555a30;
  DAT_005526d8 = DAT_00555a38;
  DAT_00552718 = DAT_00555a38;
  DAT_00552758 = DAT_00555a38;
  DAT_00552798 = DAT_00555a40;
  return;
}
