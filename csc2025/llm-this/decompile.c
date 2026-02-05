
/* WARNING: Instruction at (ram,0x00105baf) overlaps instruction at (ram,0x00105bae)
    */
/* WARNING: Removing unreachable block (ram,0x00105b3a) */
/* WARNING: Removing unreachable block (ram,0x00105b42) */
/* WARNING: Removing unreachable block (ram,0x00105b3e) */
/* WARNING: Removing unreachable block (ram,0x00105b98) */
/* WARNING: Heritage AFTER dead removal. Example location: s0xffffffffffffffc0 : 0x00105c3d */
/* WARNING: Restarted to delay deadcode elimination for space: stack */

void processEntry entry(undefined8 param_1)

{
  ulong *puVar1;
  uint uVar2;
  uint uVar3;
  undefined8 uVar4;
  int iVar5;
  uint uVar6;
  undefined8 uVar7;
  int extraout_EDX;
  ulong uVar8;
  code *pcVar9;
  code *extraout_RDX;
  code *extraout_RDX_00;
  code *extraout_RDX_01;
  code *extraout_RDX_02;
  code *extraout_RDX_03;
  code *extraout_RDX_04;
  long lVar10;
  long *plVar11;
  undefined1 *puVar12;
  undefined1 *puVar13;
  long *plVar14;
  byte bVar15;
  byte bVar16;
  byte bVar17;
  undefined1 auVar18 [16];
  long local_1040;
  undefined1 *local_1038;
  undefined8 uStack_48;
  undefined *puStack_38;
  undefined8 uStack_30;
  undefined *puStack_28;
  undefined8 local_20;
  long local_18;
  undefined8 uStack_10;
  long local_8;

  plVar11 = (long *)&stack0x00000008;
  do {
    lVar10 = *plVar11;
    plVar14 = plVar11 + 1;
    plVar11 = plVar11 + 1;
  } while (lVar10 != 0);
  do {
    plVar11 = plVar14 + 1;
    lVar10 = *plVar14;
    plVar14 = plVar11;
  } while (lVar10 != 0);
  uVar8 = 0x1000;
  do {
    puVar1 = (ulong *)(plVar11 + 1);
    lVar10 = *plVar11;
    if ((int)lVar10 == 0) goto LAB_00105b1f;
    plVar11 = plVar11 + 2;
  } while ((int)lVar10 != 6);
  uVar8 = *puVar1 & 0xffffffff;
LAB_00105b1f:
  local_8 = -uVar8;
  syscall();
  uVar4 = 0x13f;
  puStack_28 = &DAT_00105000;
  local_18 = 0xfe3;
  local_20 = 0xffffffffffffffff;
  uStack_30 = 0x908;
  puStack_38 = &DAT_001051e4;
  uVar7 = 0;
  pcVar9 = FUN_00105c80;
  lVar10 = -1;
  bVar17 = 0;
  bVar15 = 0;
  puVar12 = &DAT_00105ca4;
  plVar11 = &local_1040;
  uStack_10 = param_1;
  do {
    while ((*pcVar9)(), pcVar9 = extraout_RDX, (bool)bVar15) {
      *(undefined1 *)plVar11 = *puVar12;
      puVar12 = puVar12 + (ulong)bVar17 * -2 + 1;
      plVar11 = (long *)((long)plVar11 + (ulong)bVar17 * -2 + 1);
    }
    do {
      uVar3 = (*pcVar9)();
      bVar15 = CARRY4(uVar3,uVar3) || CARRY4(uVar3 * 2,(uint)bVar15);
      uVar3 = (*extraout_RDX_00)();
      uVar6 = (uint)uVar7;
      pcVar9 = extraout_RDX_01;
    } while (!(bool)bVar15);
    bVar15 = uVar3 < 3;
    puVar13 = puVar12;
    if (!(bool)bVar15) {
      puVar13 = puVar12 + (ulong)bVar17 * -2 + 1;
      bVar15 = false;
      uVar3 = CONCAT31((int3)uVar3 + -3,*puVar12) ^ 0xffffffff;
      if (uVar3 == 0) {
        if (puVar13 == &UNK_001068b7) {
          local_1040 = local_8;
          local_1038 = &LAB_00105c5c;
          lVar10 = local_18 + -0x10;
          do {
            iVar5 = FUN_00105c61();
          } while (extraout_EDX != iVar5);
          lVar10 = FUN_00105c61(0,lVar10,5);
          uStack_48 = 3;
          syscall();
                    /* WARNING: Could not recover jumptable at 0x00105c5a. Too many branches */
                    /* WARNING: Treating indirect jump as call */
          (*(code *)(lVar10 + 0x10))(uVar4);
          return;
        }
        do {
                    /* WARNING: Do nothing block with infinite loop */
        } while( true );
      }
      lVar10 = (long)(int)uVar3;
    }
    (*extraout_RDX_01)();
    bVar16 = CARRY4(uVar6,uVar6) || CARRY4(uVar6 * 2,(uint)bVar15);
    iVar5 = uVar6 * 2 + (uint)bVar15;
    auVar18 = (*extraout_RDX_02)();
    pcVar9 = auVar18._8_8_;
    uVar3 = auVar18._0_4_;
    uVar6 = iVar5 * 2 + (uint)bVar16;
    if (uVar6 == 0) {
      uVar8 = auVar18._0_8_ & 0xffffffff;
      bVar15 = 0xfffffffd < uVar3;
      do {
        uVar6 = (uint)uVar8;
        (*pcVar9)();
        uVar3 = (uint)bVar15;
        bVar15 = CARRY4(uVar6,uVar6) || CARRY4(uVar6 * 2,uVar3);
        uVar8 = (ulong)(uVar6 * 2 + uVar3);
        uVar3 = (*extraout_RDX_03)();
        uVar6 = (uint)uVar8;
        pcVar9 = extraout_RDX_04;
      } while (!(bool)bVar15);
    }
    uVar2 = (uint)((uint)lVar10 < 0xfffff300);
    bVar15 = CARRY4(uVar6,uVar3) || CARRY4(uVar6 + uVar3,uVar2);
    puVar12 = (undefined1 *)((long)plVar11 + lVar10);
    for (uVar8 = (ulong)(uVar6 + uVar3 + uVar2); uVar8 != 0; uVar8 = uVar8 - 1) {
      *(undefined1 *)plVar11 = *puVar12;
      puVar12 = puVar12 + (ulong)bVar17 * -2 + 1;
      plVar11 = (long *)((long)plVar11 + (ulong)bVar17 * -2 + 1);
    }
    uVar7 = 0;
    puVar12 = puVar13;
  } while( true );
}
