
#pragma once

#include <pro.h>
#include <idd.hpp>

//-------------------------------------------------------------------------
// NOTE: keep in sync with x86_register_classes
enum register_class_x86_t
{
  X86_RC_GENERAL          = 0x01, // General registers
  X86_RC_SEGMENTS         = 0x02, // Segment registers
  X86_RC_FPU              = 0x04, // FPU registers
  X86_RC_MMX              = 0x08, // MMX registers
  X86_RC_XMM              = 0x10, // XMM registers
  X86_RC_YMM              = 0x20, // YMM registers
  X86_RC_ALL = X86_RC_GENERAL
             | X86_RC_SEGMENTS
             | X86_RC_FPU
             | X86_RC_MMX
             | X86_RC_XMM
             | X86_RC_YMM
};

//-------------------------------------------------------------------------
// NOTE: keep in sync with x86_registers
enum register_x86_t
{
  // FPU registers
  R_ST0,
  R_ST1,
  R_ST2,
  R_ST3,
  R_ST4,
  R_ST5,
  R_ST6,
  R_ST7,
  R_CTRL,
  R_STAT,
  R_TAGS,
  // Segment registers
  R_CS,
  R_DS,
  R_ES,
  R_FS,
  R_GS,
  R_SS,
  // General registers
  R_EAX,
  R_EBX,
  R_ECX,
  R_EDX,
  R_ESI,
  R_EDI,
  R_EBP,
  R_ESP,
  R_EIP,
#ifdef __EA64__
  R_R8,
  R_R9,
  R_R10,
  R_R11,
  R_R12,
  R_R13,
  R_R14,
  R_R15,
#endif
  R_EFLAGS,
  // XMM registers
  R_XMM0,
  R_XMM1,
  R_XMM2,
  R_XMM3,
  R_XMM4,
  R_XMM5,
  R_XMM6,
  R_XMM7,
#ifndef __EA64__
  R_LAST_XMM = R_XMM7,
#else
  R_XMM8,
  R_XMM9,
  R_XMM10,
  R_XMM11,
  R_XMM12,
  R_XMM13,
  R_XMM14,
  R_XMM15,
  R_LAST_XMM = R_XMM15,
#endif
  R_MXCSR,
  // MMX registers
  R_MMX0,
  R_MMX1,
  R_MMX2,
  R_MMX3,
  R_MMX4,
  R_MMX5,
  R_MMX6,
  R_MMX7,
  // YMM registers
  R_YMM0,
  R_YMM1,
  R_YMM2,
  R_YMM3,
  R_YMM4,
  R_YMM5,
  R_YMM6,
  R_YMM7,
#ifndef __EA64__
  R_LAST_YMM = R_YMM7,
#else
  R_YMM8,
  R_YMM9,
  R_YMM10,
  R_YMM11,
  R_YMM12,
  R_YMM13,
  R_YMM14,
  R_YMM15,
  R_LAST_YMM = R_YMM15,
#endif
};

// Number of registers in x86 and x64
#define X86_X64_NREGS 76
#define X86_X86_NREGS 52

#ifdef __EA64__
  #define X86_NREGS X86_X64_NREGS
#else
  #define X86_NREGS X86_X86_NREGS
#endif

//-------------------------------------------------------------------------
// General registers
#ifdef __EA64__
extern register_info_t r_rax;
extern register_info_t r_rbx;
extern register_info_t r_rcx;
extern register_info_t r_rdx;
extern register_info_t r_rsi;
extern register_info_t r_rdi;
extern register_info_t r_rbp;
extern register_info_t r_rsp;
extern register_info_t r_rip;
extern register_info_t r_r8;
extern register_info_t r_r9;
extern register_info_t r_r10;
extern register_info_t r_r11;
extern register_info_t r_r12;
extern register_info_t r_r13;
extern register_info_t r_r14;
extern register_info_t r_r15;
#endif
extern register_info_t r_eax;
extern register_info_t r_ebx;
extern register_info_t r_ecx;
extern register_info_t r_edx;
extern register_info_t r_esi;
extern register_info_t r_edi;
extern register_info_t r_ebp;
extern register_info_t r_esp;
extern register_info_t r_eip;

//-------------------------------------------------------------------------
extern const char *x86_register_classes[];
extern register_info_t x86_registers[X86_NREGS];

//-------------------------------------------------------------------------
int x86_get_regidx(int *clsmask, const char *regname);
int x86_get_regclass(int idx);
