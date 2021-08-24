/*
*      Interactive disassembler (IDA).
*      Copyright (c) 1990-2021 Hex-Rays
*      ALL RIGHTS RESERVED.
*
*/

#ifndef __INSTRS_HPP
#define __INSTRS_HPP

#include "necv850.hpp"

//----------------------------------------------------------------------

extern const instruc_t Instructions[];

enum NEC850_Instructions
{
  NEC850_NULL = 0,

  NEC850_BREAKPOINT,
  NEC850_XORI,
  NEC850_XOR,
  NEC850_TST1,
  NEC850_TST,
  NEC850_TRAP,
  NEC850_SUBR,
  NEC850_SUB,
  NEC850_STSR,
  NEC850_ST_B,
  NEC850_ST_H,
  NEC850_ST_W,
  NEC850_SST_B,
  NEC850_SST_H,
  NEC850_SST_W,
  NEC850_SLD_B,
  NEC850_SLD_H,
  NEC850_SLD_W,
  NEC850_SHR,
  NEC850_SHL,
  NEC850_SET1,
  NEC850_SETF,
  NEC850_SATSUBR,
  NEC850_SATSUBI,
  NEC850_SATSUB,
  NEC850_SATADD,
  NEC850_SAR,
  NEC850_RETI,
  NEC850_ORI,
  NEC850_OR,
  NEC850_NOT1,
  NEC850_NOT,
  NEC850_NOP,
  NEC850_MULHI,
  NEC850_MULH,
  NEC850_MOVHI,
  NEC850_MOVEA,
  NEC850_MOV,
  NEC850_LDSR,
  NEC850_LD_B,
  NEC850_LD_H,
  NEC850_LD_W,
  NEC850_JR,
  NEC850_JMP,
  NEC850_JARL,
  NEC850_HALT,
  NEC850_EI,
  NEC850_DIVH,
  NEC850_DI,
  NEC850_CMP,
  NEC850_CLR1,
  NEC850_BV,
  NEC850_BL,
  NEC850_BZ,
  NEC850_BNH,
  NEC850_BN,
  NEC850_BR,
  NEC850_BLT,
  NEC850_BLE,
  NEC850_BNV,
  NEC850_BNC,
  NEC850_BNZ,
  NEC850_BH,
  NEC850_BP,
  NEC850_BSA,
  NEC850_BGE,
  NEC850_BGT,
  NEC850_ANDI,
  NEC850_AND,
  NEC850_ADDI,
  NEC850_ADD,

  //
  // V850E/E1/ES
  //
  NEC850_SWITCH,
  NEC850_ZXB,
  NEC850_SXB,
  NEC850_ZXH,
  NEC850_SXH,
  NEC850_DISPOSE_r0,
  NEC850_DISPOSE_r,
  NEC850_CALLT,
  NEC850_DBTRAP,
  NEC850_DBRET,
  NEC850_CTRET,

  NEC850_SASF,

  NEC850_PREPARE_sp,
  NEC850_PREPARE_i,

  NEC850_MUL,
  NEC850_MULU,

  NEC850_DIVH_r3,
  NEC850_DIVHU,
  NEC850_DIV,
  NEC850_DIVU,

  NEC850_BSW,
  NEC850_BSH,
  NEC850_HSW,

  NEC850_CMOV,

  NEC850_SLD_BU,
  NEC850_SLD_HU,
  NEC850_LD_BU,
  NEC850_LD_HU,

  //
  // V850E2
  //
  NEC850_ADF,        // Add on condition flag

  NEC850_HSH,        // Halfword swap halfword
  NEC850_MAC,        // Multiply and add word
  NEC850_MACU,       // Multiply and add word unsigned

  NEC850_SBF,        // Subtract on condition flag

  NEC850_SCH0L,      // Search zero from left
  NEC850_SCH0R,      // Search zero from right
  NEC850_SCH1L,      // Search one from left
  NEC850_SCH1R,      // Search one from right

  //
  // V850E2M
  //
  NEC850_CAXI,       // Compare and exchange for interlock
  NEC850_DIVQ,       // Divide word quickly
  NEC850_DIVQU,      // Divide word unsigned quickly
  NEC850_EIRET,      // Return from EI level exception
  NEC850_FERET,      // Return from FE level exception
  NEC850_FETRAP,     // FE-level Trap
  NEC850_RMTRAP,     // Runtime monitor trap
  NEC850_RIE,        // Reserved instruction exception
  NEC850_SYNCE,      // Synchronize exceptions
  NEC850_SYNCM,      // Synchronize memory
  NEC850_SYNCP,      // Synchronize pipeline
  NEC850_SYSCALL,    // System call

  // floating point (E1F only)
  NEC850_CVT_SW,     // Real to integer conversion
  NEC850_TRNC_SW,    // Real to integer conversion
  NEC850_CVT_WS,     // Integer to real conversion
  NEC850_LDFC,       // Load to Floating Controls
  NEC850_LDFF,       // Load to Floating Flags
  NEC850_STFC,       // Store Floating Controls
  NEC850_STFF,       // Store Floating Flags
  NEC850_TRFF,       // Transfer Floating Flags

  // floating point (E2M)

  NEC850_ABSF_D,     // Floating-point Absolute Value (Double)
  NEC850_ABSF_S,     // Floating-point Absolute Value (Single)
  NEC850_ADDF_D,     // Floating-point Add (Double)
  NEC850_ADDF_S,     // Floating-point Add (Single)
  NEC850_DIVF_D,     // Floating-point Divide (Double)
  NEC850_DIVF_S,     // Floating-point Divide (Single)
  NEC850_MAXF_D,     // Floating-point Maximum (Double)
  NEC850_MAXF_S,     // Floating-point Maximum (Single)
  NEC850_MINF_D,     // Floating-point Minimum (Double)
  NEC850_MINF_S,     // Floating-point Minimum (Single)
  NEC850_MULF_D,     // Floating-point Multiply (Double)
  NEC850_MULF_S,     // Floating-point Multiply (Single)
  NEC850_NEGF_D,     // Floating-point Negate (Double)
  NEC850_NEGF_S,     // Floating-point Negate (Single)
  NEC850_RECIPF_D,   // Reciprocal of a floating-point value (Double)
  NEC850_RECIPF_S,   // Reciprocal of a floating-point value (Single

  NEC850_RSQRTF_D,   // Reciprocal of the square root of a floating-point value (Double)
  NEC850_RSQRTF_S,   // Reciprocal of the square root of a floating-point value (Single)
  NEC850_SQRTF_D,    // Floating-point Square Root (Double)
  NEC850_SQRTF_S,    // Floating-point Square Root (Single)
  NEC850_SUBF_D,     // Floating-point Subtract (Double)
  NEC850_SUBF_S,     // Floating-point Subtract (Single)
  NEC850_MADDF_S,    // Floating-point Multiply-Add (Single)
  NEC850_MSUBF_S,    // Floating-point Multiply-Subtract (Single)
  NEC850_NMADDF_S,   // Floating-point Negate Multiply-Add (Single)
  NEC850_NMSUBF_S,   // Floating-point Negate Multiply-Subtract (Single)

  NEC850_CEILF_DL,   // Floating-point Truncate to Long Fixed-point Format, rounded toward +inf (Double)
  NEC850_CEILF_DW,   // Floating-point Truncate to Single Fixed-point Format, rounded toward +inf (Double)
  NEC850_CEILF_SL,   // Floating-point Truncate to Long Fixed-point Format, rounded toward +inf (Single)
  NEC850_CEILF_SW,   // Floating-point Truncate to Single Fixed-point Format, rounded toward +inf (Single)
  NEC850_CEILF_DUL,  // Floating-point Truncate to Unsigned Long, rounded toward +inf (Double)
  NEC850_CEILF_DUW,  // Floating-point Truncate to Unsigned Word, rounded toward +inf (Double)
  NEC850_CEILF_SUL,  // Floating-point Truncate to Unsigned Long, rounded toward +inf (Single)
  NEC850_CEILF_SUW,  // Floating-point Truncate to Unsigned Word, rounded toward +inf (Single)
  NEC850_CVTF_DL,    // Floating-point Convert to Long Fixed-point Format (Double)
  NEC850_CVTF_DS,    // Floating-point Convert to Single Floating-point Format (Double)
  NEC850_CVTF_DUL,   // Floating-point Convert Double to Unsigned-Long (Double)
  NEC850_CVTF_DUW,   // Floating-point Convert Double to Unsigned-Word (Double)
  NEC850_CVTF_DW,    // Floating-point Convert to Single Fixed-point Format (Double)
  NEC850_CVTF_LD,    // Floating-point Convert to Single Floating-point Format (Double)
  NEC850_CVTF_LS,    // Floating-point Convert to Single Floating-point Format (Single)
  NEC850_CVTF_SD,    // Floating-point Convert to Double Floating-point Format (Double)
  NEC850_CVTF_SL,    // Floating-point Convert to Long Fixed-point Format (Single)
  NEC850_CVTF_SUL,   // Floating-point Convert Single to Unsigned-Long (Single)
  NEC850_CVTF_SUW,   // Floating-point Convert Single to Unsigned-Word (Single)
  NEC850_CVTF_SW,    // Floating-point Convert to Single Fixed-point Format (Single)
  NEC850_CVTF_ULD,   // Floating-point Convert Unsigned-Long to Double (Double)
  NEC850_CVTF_ULS,   // Floating-point Convert Unsigned-Long to Single (Single)
  NEC850_CVTF_UWD,   // Floating-point Convert Unsigned-Word to Double (Double)
  NEC850_CVTF_UWS,   // Floating-point Convert Unsigned-Word to Single (Single)
  NEC850_CVTF_WD,    // Floating-point Convert to Single Floating-point Format (Double)
  NEC850_CVTF_WS,    // Floating-point Convert to Single Floating-point Format (Single)
  NEC850_FLOORF_DL,  // Floating-point Truncate to Long Fixed-point Format, rounded toward -inf (Double)
  NEC850_FLOORF_DW,  // Floating-point Truncate to Single Fixed-point Format, rounded toward -inf (Double)
  NEC850_FLOORF_SL,  // Floating-point Truncate to Long Fixed-point Format, rounded toward -inf (Single)
  NEC850_FLOORF_SW,  // Floating-point Truncate to Single Fixed-point Format, rounded toward -inf (Single)
  NEC850_FLOORF_DUL, // Floating-point Truncate to Unsigned Long, rounded toward -inf (Double)
  NEC850_FLOORF_DUW, // Floating-point Truncate to Unsigned Word, rounded toward -inf (Double)
  NEC850_FLOORF_SUL, // Floating-point Truncate to Unsigned Long, rounded toward -inf (Single)
  NEC850_FLOORF_SUW, // Floating-point Truncate to Unsigned Word, rounded toward -inf (Single)
  NEC850_TRNCF_DL,   // Floating-point Truncate to Long Fixed-point Format, rounded to zero (Double)
  NEC850_TRNCF_DUL,  // Floating-point Truncate Double to Unsigned-Long (Double)
  NEC850_TRNCF_DUW,  // Floating-point Truncate Double to Unsigned-Word (Double)
  NEC850_TRNCF_DW,   // Floating-point Truncate to Single Fixed-point Format, rounded to zero (Double)
  NEC850_TRNCF_SL,   // Floating-point Truncate to Long Fixed-point Format, rounded to zero (Single)
  NEC850_TRNCF_SUL,  // Floating-point Truncate Single to Unsigned-Long (Single)
  NEC850_TRNCF_SUW,  // Floating-point Truncate Single to Unsigned-Word (Single)
  NEC850_TRNCF_SW,   // Floating-point Truncate to Single Fixed-point Format, rounded to zero (Single)
  NEC850_CMPF_S,     // Compares floating-point values (Single)
  NEC850_CMPF_D,     // Compares floating-point values (Double)
  NEC850_CMOVF_S,    // Floating-point conditional move (Single)
  NEC850_CMOVF_D,    // Floating-point conditional move (Double)
  NEC850_TRFSR,      // Transfers specified CC bit to Zero flag in PSW (Single)

  //
  // RH850
  //
  NEC850_SYNCI,      // Synchronize instruction pipeline
  NEC850_SNOOZE,     // Snooze
  NEC850_BINS,       // Bitfield Insert
  NEC850_ROTL,       // Rotate Left
  NEC850_LOOP,       // Loop
  NEC850_LD_DW,      // Load Double Word
  NEC850_ST_DW,      // Store Double Word
  NEC850_LDL_W,      // Load Linked
  NEC850_STC_W,      // Store Conditional
  NEC850_CLL,        // Clear Load Link
  NEC850_CACHE,      // Cache operation
  NEC850_PREF,       // Prefetch
  NEC850_PUSHSP,     // Push registers to Stack
  NEC850_POPSP,      // Pop registers from Stack

  // new RH850 FP instructions
  NEC850_CVTF_HS,    // Floating-point Convert Half to Single (Single)
  NEC850_CVTF_SH,    // Floating-point Convert Single to Half (Single)
  NEC850_FMAF_S,     // Floating-point Fused-Multiply-add (Single)
  NEC850_FMSF_S,     // Floating-point Fused-Multiply-subtract (Single)
  NEC850_FNMAF_S,    // Floating-point Fused-Negate-Multiply-add (Single)
  NEC850_FNMSF_S,    // Floating-point Fused-Negate-Multiply-subtract (Single)

  // debug instructions
  NEC850_DBPUSH,     //
  NEC850_DBCP,       //
  NEC850_DBTAG,      //
  NEC850_DBHVTRAP,   //

  // virtualization instructions
  NEC850_EST,        //
  NEC850_DST,        //
  NEC850_HVTRAP,     //
  NEC850_HVCALL,     //
  NEC850_LDVC_SR,    //
  NEC850_STVC_SR,    //
  NEC850_LDTC_GR,    //
  NEC850_STTC_GR,    //
  NEC850_LDTC_PC,    //
  NEC850_STTC_PC,    //
  NEC850_LDTC_SR,    //
  NEC850_STTC_SR,    //
  NEC850_LDTC_VR,    //
  NEC850_STTC_VR,    //

  // TLB instructions
  NEC850_TLBAI,      //
  NEC850_TLBR,       //
  NEC850_TLBS,       //
  NEC850_TLBVI,      //
  NEC850_TLBW,       //

  NEC850_LAST_INSTRUCTION
};

#endif
