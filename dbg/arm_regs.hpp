
#pragma once

#include <pro.h>
#include <idd.hpp>

//-------------------------------------------------------------------------
#if defined(__LINUX__) && defined(__ARM__) && !defined(__EA64__)
#  define __HAVE_ARM_VFP__
#endif

//-------------------------------------------------------------------------
#if defined(__MAC__) && defined(__ARM__)
#  define __HAVE_ARM_NEON__
#endif

//-------------------------------------------------------------------------
// NOTE: keep in sync with arm_register_classes
enum register_class_arm_t
{
  ARM_RC_GENERAL          = 0x01, // General registers
  ARM_RC_VFP              = 0x02, // VFP registers
  ARM_RC_NEON             = 0x04, // NEON registers
  ARM_RC_ALL = ARM_RC_GENERAL
#ifdef __HAVE_ARM_VFP__
             | ARM_RC_VFP
#endif
#ifdef __HAVE_ARM_NEON__
             | ARM_RC_NEON
#endif
};

//-------------------------------------------------------------------------

//-------------------------------------------------------------------------
// NOTE: keep in sync with arm_registers
enum register_arm_t
{
#ifndef __EA64__
  // General registers
  R_R0,
  R_R1,
  R_R2,
  R_R3,
  R_R4,
  R_R5,
  R_R6,
  R_R7,
  R_R8,
  R_R9,
  R_R10,
  R_R11,
  R_R12,
  R_SP,
  R_LR,
  R_PC,
  R_PSR,
  // VFP registers
  R_D0,
  R_D1,
  R_D2,
  R_D3,
  R_D4,
  R_D5,
  R_D6,
  R_D7,
  R_D8,
  R_D9,
  R_D10,
  R_D11,
  R_D12,
  R_D13,
  R_D14,
  R_D15,
  R_D16,
  R_D17,
  R_D18,
  R_D19,
  R_D20,
  R_D21,
  R_D22,
  R_D23,
  R_D24,
  R_D25,
  R_D26,
  R_D27,
  R_D28,
  R_D29,
  R_D30,
  R_D31,
  R_FPSCR,
#else
  // General registers
  R_R0,
  R_R1,
  R_R2,
  R_R3,
  R_R4,
  R_R5,
  R_R6,
  R_R7,
  R_R8,
  R_R9,
  R_R10,
  R_R11,
  R_R12,
  R_R13,
  R_R14,
  R_R15,
  R_R16,
  R_R17,
  R_R18,
  R_R19,
  R_R20,
  R_R21,
  R_R22,
  R_R23,
  R_R24,
  R_R25,
  R_R26,
  R_R27,
  R_R28,
  R_R29,
  R_LR,
  R_SP,
  R_PC,
  R_PSR,
  // NEON registers
  R_V0,
  R_V1,
  R_V2,
  R_V3,
  R_V4,
  R_V5,
  R_V6,
  R_V7,
  R_V8,
  R_V9,
  R_V10,
  R_V11,
  R_V12,
  R_V13,
  R_V14,
  R_V15,
  R_V16,
  R_V17,
  R_V18,
  R_V19,
  R_V20,
  R_V21,
  R_V22,
  R_V23,
  R_V24,
  R_V25,
  R_V26,
  R_V27,
  R_V28,
  R_V29,
  R_V30,
  R_V31,
  R_FPSR,
  R_FPCR,
#endif
};

// Number of registers in arm and aarch64
#define ARM64_NREGS 68
#define ARM32_NREGS 50

#ifdef __EA64__
  #define ARM_NREGS ARM64_NREGS
#else
  #define ARM_NREGS ARM32_NREGS
#endif

//-------------------------------------------------------------------------
extern const char *arm_register_classes[];
extern register_info_t arm_registers[ARM_NREGS];

//-------------------------------------------------------------------------
int arm_get_regidx(int *clsmask, const char *regname);
int arm_get_regclass(int idx);
