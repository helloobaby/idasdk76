/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-2021 Hex-Rays
 *      ALL RIGHTS RESERVED.
 *
 */

#ifndef __INSTRS_HPP
#define __INSTRS_HPP

extern const instruc_t Instructions[];

enum nameNum ENUM_SIZE(uint16)
{

I860_null = 0,          // Unknown Operation

//
//      Intel 860 XP instructions
//

I860_adds,
I860_addu,
I860_and,
I860_andh,
I860_andnot,
I860_andnoth,
I860_bc,
I860_bc_t,
I860_bla,
I860_bnc,
I860_bnc_t,
I860_br,
I860_bri,
I860_bte,
I860_btne,
I860_call,
I860_calli,
I860_fadd,
I860_faddp,
I860_faddz,
I860_famov,
I860_fiadd,
I860_fisub,
I860_fix,
I860_fld,
I860_flush,
I860_fmlow_dd,
I860_fmul,
I860_form,
I860_frcp,
I860_frsqr,
I860_fst,
I860_fsub,
I860_ftrunc,
I860_fxfr,
I860_fzchkl,
I860_fzchks,
I860_introvr,
I860_ixfr,
I860_ld_c,
I860_ld,
I860_ldint,
I860_ldio,
I860_lock,
I860_or,
I860_orh,
I860_pfadd,
I860_pfaddp,
I860_pfaddz,
I860_pfamov,
I860_pfeq,
I860_pfgt,
I860_pfiadd,
I860_pfisub,
I860_pfix,
I860_pfld,
I860_pfle,
I860_pfmul,
I860_pfmul3_dd,
I860_pform,
I860_pfsub,
I860_pftrunc,
I860_pfzchkl,
I860_pfzchks,
I860_pst_d,
I860_scyc,
I860_shl,
I860_shr,
I860_shra,
I860_shrd,
I860_st_c,
I860_st,
I860_stio,
I860_subs,
I860_subu,
I860_trap,
I860_unlock,
I860_xor,
I860_xorh,
//
// iNTEL 860 XP Pipelined F-P instructions
//
I860_r2p1,
I860_r2pt,
I860_r2ap1,
I860_r2apt,
I860_i2p1,
I860_i2pt,
I860_i2ap1,
I860_i2apt,
I860_rat1p2,
I860_m12apm,
I860_ra1p2,
I860_m12ttpa,
I860_iat1p2,
I860_m12tpm,
I860_ia1p2,
I860_m12tpa,
I860_r2s1,
I860_r2st,
I860_r2as1,
I860_r2ast,
I860_i2s1,
I860_i2st,
I860_i2as1,
I860_i2ast,
I860_rat1s2,
I860_m12asm,
I860_ra1s2,
I860_m12ttsa,
I860_iat1s2,
I860_m12tsm,
I860_ia1s2,
I860_m12tsa,
I860_mr2p1,
I860_mr2pt,
I860_mr2mp1,
I860_mr2mpt,
I860_mi2p1,
I860_mi2pt,
I860_mi2mp1,
I860_mi2mpt,
I860_mrmt1p2,
I860_mm12mpm,
I860_mrm1p2,
I860_mm12ttpm,
I860_mimt1p2,
I860_mm12tpm,
I860_mim1p2,
I860_mr2s1,
I860_mr2st,
I860_mr2ms1,
I860_mr2mst,
I860_mi2s1,
I860_mi2st,
I860_mi2ms1,
I860_mi2mst,
I860_mrmt1s2,
I860_mm12msm,
I860_mrm1s2,
I860_mm12ttsm,
I860_mimt1s2,
I860_mm12tsm,
I860_mim1s2,

I860_last,

    };

#endif
